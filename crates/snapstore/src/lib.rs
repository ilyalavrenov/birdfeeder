//! Stores snapshot memory in an S3-compatible bucket so restored guests' page-fault handlers can read it by range.

use std::{num::NonZeroU64, path::Path, time::Duration};

use anyhow::{Context as _, ensure};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{
    Client,
    config::{RequestChecksumCalculation, ResponseChecksumValidation},
    presigning::PresigningConfig,
    primitives::{ByteStream, Length},
    types::{CompletedMultipartUpload, CompletedPart},
};
use aws_smithy_http_client::tls;
use futures_util::{StreamExt as _, TryStreamExt as _, stream};
use serde::{Deserialize, Deserializer};

/// S3 takes at most 10,000 parts, so this covers up to 80 GiB.
const PART_BYTES: u64 = 8 << 20;
const PARTS_IN_FLIGHT: usize = 5;

/// The bucket. Credentials come from the AWS SDK's usual chain: `AWS_ACCESS_KEY_ID` and friends in the
/// environment, profiles, SSO, or the instance role.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// The S3 API's base URL; absent means AWS's endpoint for the region.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    /// Puts the bucket in the URL path instead of the host. Most self-hosted stores want this.
    #[serde(default)]
    pub path_style: bool,
    /// How long a restored guest's handler has to pull its memory in.
    #[serde(rename = "presign_ttl_sec", default = "default_presign_ttl", deserialize_with = "positive_secs")]
    pub presign_ttl: Duration,
}

fn default_presign_ttl() -> Duration {
    Duration::from_mins(15)
}

fn positive_secs<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    NonZeroU64::deserialize(d).map(|s| Duration::from_secs(s.get()))
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(!self.bucket.is_empty() && !self.region.is_empty(), "snapshot_store needs a bucket and a region");
        Ok(())
    }
}

pub struct Store {
    client: Client,
    bucket: String,
    prefix: String,
    presign_ttl: Duration,
}

impl Store {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        config.validate()?;
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
            .build_https();
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .http_client(http)
            // S3's newer default checksums use aws-chunked uploads, and not every compatible store takes those.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            .load()
            .await;
        let mut s3 = aws_sdk_s3::config::Builder::from(&shared).force_path_style(config.path_style);
        if let Some(endpoint) = &config.endpoint {
            s3 = s3.endpoint_url(endpoint);
        }
        Ok(Self {
            client: Client::from_conf(s3.build()),
            bucket: config.bucket.clone(),
            prefix: config.prefix.clone(),
            presign_ttl: config.presign_ttl,
        })
    }

    /// `parts` under the configured prefix, joined by slashes.
    #[must_use]
    pub fn key(&self, parts: &[&str]) -> String {
        key(&self.prefix, parts)
    }

    /// Uploads `file` to `key`, in parts if it's bigger than one.
    pub async fn put(&self, key: &str, file: &Path) -> anyhow::Result<()> {
        let len = tokio::fs::metadata(file).await.with_context(|| format!("stat {}", file.display()))?.len();
        if len <= PART_BYTES {
            let body = ByteStream::from_path(file).await.with_context(|| format!("open {}", file.display()))?;
            self.client.put_object().bucket(&self.bucket).key(key).body(body).send().await.with_context(|| format!("upload {key}"))?;
            return Ok(());
        }
        let upload = self.client.create_multipart_upload().bucket(&self.bucket).key(key).send().await;
        let upload = upload.with_context(|| format!("start uploading {key}"))?;
        let id = upload.upload_id().with_context(|| format!("start uploading {key}: no upload id"))?;
        let uploaded = self.put_parts(key, id, file, len).await;
        if uploaded.is_err() {
            // a failed upload's parts get billed until it's aborted. the original error is the one worth reporting.
            let _ = self.client.abort_multipart_upload().bucket(&self.bucket).key(key).upload_id(id).send().await;
        }
        uploaded.with_context(|| format!("upload {key}"))
    }

    async fn put_parts(&self, key: &str, id: &str, file: &Path, len: u64) -> anyhow::Result<()> {
        let parts = stream::iter((0..len.div_ceil(PART_BYTES)).map(|i| async move {
            let offset = i * PART_BYTES;
            let body =
                ByteStream::read_from().path(file).offset(offset).length(Length::Exact(PART_BYTES.min(len - offset))).build().await?;
            let number = i32::try_from(i + 1)?;
            let part = self.client.upload_part().bucket(&self.bucket).key(key).upload_id(id).part_number(number).body(body).send().await?;
            anyhow::Ok(CompletedPart::builder().part_number(number).set_e_tag(part.e_tag).build())
        }))
        .buffered(PARTS_IN_FLIGHT)
        .try_collect::<Vec<_>>()
        .await?;
        let parts = CompletedMultipartUpload::builder().set_parts(Some(parts)).build();
        self.client.complete_multipart_upload().bucket(&self.bucket).key(key).upload_id(id).multipart_upload(parts).send().await?;
        Ok(())
    }

    /// A presigned GET of `key` that anything supporting `Range` can read without credentials.
    pub async fn url(&self, key: &str) -> anyhow::Result<String> {
        let presigning = PresigningConfig::expires_in(self.presign_ttl)?;
        let request = self.client.get_object().bucket(&self.bucket).key(key).presigned(presigning).await;
        Ok(request.with_context(|| format!("presign {key}"))?.uri().to_owned())
    }
}

fn key(prefix: &str, parts: &[&str]) -> String {
    let segments = prefix.split('/').chain(parts.iter().flat_map(|p| p.split('/')));
    segments.filter(|s| !s.is_empty()).collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presign_ttl_is_positive_seconds() {
        let parse = |ttl: u64| serde_json::from_value::<Config>(serde_json::json!({"region": "r", "bucket": "b", "presign_ttl_sec": ttl}));
        assert_eq!(parse(60).unwrap().presign_ttl, Duration::from_mins(1));
        assert!(parse(0).is_err());
    }

    #[test]
    fn keys_join_under_the_prefix() {
        assert_eq!(key("", &["host", "tpl", "mem"]), "host/tpl/mem");
        assert_eq!(key("snaps/", &["host", "tpl"]), "snaps/host/tpl");
        assert_eq!(key("/a//b", &["c/d", "e"]), "a/b/c/d/e");
    }
}
