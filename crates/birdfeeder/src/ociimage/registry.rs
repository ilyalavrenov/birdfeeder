//! Pulls an image's config and layers from a registry with the local Docker credentials.

use std::{fmt, net::IpAddr, path::Path, str::FromStr};

use anyhow::{Context as _, Result, anyhow, bail};
use oci_client::{
    Client, Reference,
    client::{ClientConfig, ClientProtocol},
    manifest::ImageIndexEntry,
    secrets::RegistryAuth,
};
use tempfile::NamedTempFile;

use super::spec::{ConfigFile, ImageConfig};

/// An os[/arch[/variant]][:osversion] platform, as `docker --platform` takes it. A field left out matches any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    os: Option<String>,
    arch: Option<String>,
    variant: Option<String>,
    os_version: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("too many slashes in platform spec: {0}")]
pub struct InvalidPlatform(String);

impl Platform {
    fn satisfied_by(&self, entry: &ImageIndexEntry) -> bool {
        let Some(p) = &entry.platform else { return false };
        let field = |want: &Option<String>, have: String| want.as_ref().is_none_or(|w| *w == have);
        field(&self.os, p.os.to_string())
            && field(&self.arch, p.architecture.to_string())
            && self.variant.as_ref().is_none_or(|v| p.variant.as_ref() == Some(v))
            && self.os_version.as_ref().is_none_or(|v| p.os_version.as_ref() == Some(v))
    }

    fn resolve(&self, entries: &[ImageIndexEntry]) -> Option<String> {
        entries.iter().find(|e| self.satisfied_by(e)).map(|e| e.digest.clone())
    }
}

/// The host's platform. Guests share it.
impl Default for Platform {
    fn default() -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self { os: Some("linux".into()), arch: Some(arch.into()), variant: None, os_version: None }
    }
}

impl FromStr for Platform {
    type Err = InvalidPlatform;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rest, os_version) = match s.split_once(':') {
            Some((rest, v)) => (rest, Some(v.to_owned())),
            None => (s, None),
        };
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() > 3 {
            return Err(InvalidPlatform(s.to_owned()));
        }
        let part = |i: usize| parts.get(i).filter(|p| !p.is_empty()).map(|p| (*p).to_owned());
        Ok(Self { os: part(0), arch: part(1), variant: part(2), os_version })
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os.as_deref().unwrap_or_default(), self.arch.as_deref().unwrap_or_default())?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        if let Some(v) = &self.os_version {
            write!(f, ":{v}")?;
        }
        Ok(())
    }
}

/// An image ready to flatten.
pub struct Pulled {
    /// the repository and manifest digest that was pulled, so a tag can be pinned.
    pub image: String,
    pub config: ImageConfig,
    /// compressed layers, bottom first, each verified against its digest.
    pub layers: Vec<NamedTempFile>,
}

/// Pulls reference for platform. Layers stay in dir until the returned value drops. Registries in insecure
/// (`host[:port]`) and loopback ones get plain HTTP.
pub async fn pull(reference: &str, platform: &Platform, insecure: &[String], dir: &Path) -> Result<Pulled> {
    let image: Reference = reference.parse().context("parse image reference")?;
    let auth = credentials(&image)?;
    let registry = image.resolve_registry().to_owned();
    let resolver = platform.clone();
    let client = Client::new(ClientConfig {
        protocol: if plain_http(&registry, image.registry(), insecure) { ClientProtocol::Http } else { ClientProtocol::Https },
        platform_resolver: Some(Box::new(move |entries| resolver.resolve(entries))),
        ..ClientConfig::default()
    });
    let fetch = |e: oci_client::errors::OciDistributionError| anyhow!(e).context(format!("fetch {}", image.whole()));
    let (manifest, digest, config) = client.pull_manifest_and_config(&image, &auth).await.map_err(fetch)?;
    let config: ConfigFile = serde_json::from_str(&config).context("parse image config")?;
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for layer in &manifest.layers {
        let file = tempfile::Builder::new().prefix(".ociimage-layer-").tempfile_in(dir).context("create layer file")?;
        let out = tokio::fs::File::from_std(file.reopen().context("open layer file")?);
        client.pull_blob(&image, layer, out).await.map_err(fetch)?;
        layers.push(file);
    }
    Ok(Pulled { image: format!("{}/{}@{digest}", image.registry(), image.repository()), config: config.config, layers })
}

/// Docker's credentials for the image's registry, from config.json or a credential helper. None means anonymous.
fn credentials(image: &Reference) -> Result<RegistryAuth> {
    use docker_credential::{CredentialRetrievalError as E, DockerCredential};
    let server = match image.registry() {
        "docker.io" | "index.docker.io" | "registry-1.docker.io" => "https://index.docker.io/v1/",
        other => other,
    };
    match docker_credential::get_credential(server) {
        Ok(DockerCredential::UsernamePassword(user, password)) => Ok(RegistryAuth::Basic(user, password)),
        Ok(DockerCredential::IdentityToken(_)) => bail!("{server} has an identity token, which isn't supported; log in with a password"),
        Err(E::ConfigNotFound | E::ConfigReadError | E::NoCredentialConfigured) => Ok(RegistryAuth::Anonymous),
        Err(e) => Err(anyhow!(e).context(format!("read credentials for {server}"))),
    }
}

/// Loopback registries (local and test ones) get plain HTTP, and so do the ones the caller named. Everything else
/// gets TLS, private networks too. Credentials go out with every request, and anyone on the path could swap a tag
/// resolved without TLS.
fn plain_http(resolved: &str, named: &str, insecure: &[String]) -> bool {
    if insecure.iter().any(|r| r == resolved || r == named) {
        return true;
    }
    let host = resolved.rsplit_once(':').map_or(resolved, |(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { resolved });
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::variant("linux/arm64/v8")]
    #[case::os_version("windows/amd64:10.0.17763")]
    #[case::any_arch("linux/")]
    fn platforms_round_trip(#[case] spec: &str) {
        assert_eq!(spec.parse::<Platform>().unwrap().to_string(), spec);
    }

    #[test]
    fn platforms() {
        assert!("a/b/c/d".parse::<Platform>().is_err());
        assert_eq!("linux".parse::<Platform>().unwrap().arch, None, "a field left out matches any");
        let host = Platform::default();
        assert_eq!(host.os.as_deref(), Some("linux"));
        assert_eq!(host.to_string().parse::<Platform>().unwrap(), host, "clap shows the default and parses it back");
    }

    #[rstest]
    #[case::loopback_v4("127.0.0.1:5000", true)]
    #[case::localhost("localhost:5000", true)]
    #[case::loopback_v6("[::1]:5000", true)]
    #[case::loopback_v4_range_no_port("127.1.2.3", true)]
    #[case::ghcr("ghcr.io", false)]
    #[case::docker_hub("docker.io", false)]
    #[case::localhost_lookalike("localhost.example.com", false)]
    #[case::public_ip("8.8.8.8:443", false)]
    #[case::private_v4("10.1.2.3", false)]
    #[case::private_v4_port("192.168.0.1:80", false)]
    #[case::private_v6("[fd00::1]:5000", false)]
    fn plain_http_registries(#[case] registry: &str, #[case] plain: bool) {
        assert_eq!(plain_http(registry, registry, &[]), plain);
    }

    #[rstest]
    #[case::named_with_port("10.0.0.5:5000", true)]
    #[case::named_host("registry.lan", true)]
    #[case::another_port_of_a_named_host("10.0.0.5", false)]
    #[case::unnamed("10.0.0.6:5000", false)]
    fn insecure_registries_are_named_exactly(#[case] registry: &str, #[case] plain: bool) {
        let insecure = ["10.0.0.5:5000".to_owned(), "registry.lan".to_owned()];
        assert_eq!(plain_http(registry, registry, &insecure), plain);
    }
}
