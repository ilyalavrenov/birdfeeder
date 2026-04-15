//! Guest logs export as their own service, each guest under its own resource, through the host's export queue. A guest
//! logger's scope carries its resource, and the exporter swaps that in for the logger's records.

use std::fmt;

use opentelemetry::{InstrumentationScope, KeyValue, logs::LoggerProvider as _};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    logs::{LogBatch, LogExporter, SdkLogRecord, SdkLogger, SdkLoggerProvider},
};

const GUEST_SCOPE: &str = "birdfeeder.guest";

/// Makes loggers for guest workloads. Their records share the host's bounded queue, so a noisy guest drops records
/// instead of blocking or eating the host's memory.
#[derive(Clone, Debug)]
pub struct GuestLogs {
    provider: SdkLoggerProvider,
    /// The host's resource, minus whatever describes the host's own process and service.
    inherited: Vec<KeyValue>,
}

impl GuestLogs {
    pub(super) fn new(provider: SdkLoggerProvider, host: &Resource) -> Self {
        let own = |key: &str| key.starts_with("process.") || key.starts_with("service.");
        let inherited = host.iter().filter(|(k, _)| !own(k.as_str())).map(|(k, v)| KeyValue::new(k.clone(), v.clone())).collect();
        Self { provider, inherited }
    }

    /// A logger whose records export under the host's resource overlaid with `attributes`, as service
    /// `birdfeeder.guest`.
    pub fn logger(&self, attributes: impl IntoIterator<Item = KeyValue>) -> SdkLogger {
        // last duplicate wins, so the guest's attributes override anything it inherits.
        let resource = Resource::builder_empty()
            .with_attributes(self.inherited.iter().cloned().chain(attributes).chain([KeyValue::new("service.name", GUEST_SCOPE)]))
            .build();
        let attributes = resource.iter().map(|(k, v)| KeyValue::new(k.clone(), v.clone()));
        self.provider.logger_with_scope(InstrumentationScope::builder(GUEST_SCOPE).with_attributes(attributes).build())
    }
}

/// Wraps the host's exporter so each guest scope's records export under the resource the scope carries.
pub(super) struct Routed<E> {
    // export and set_resource take turns on one exporter. the batch processor only exports one batch at a time anyway.
    inner: tokio::sync::Mutex<E>,
    host: Resource,
    guest_scope: InstrumentationScope,
}

impl<E> Routed<E> {
    pub(super) fn new(inner: E) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(inner),
            host: Resource::builder_empty().build(),
            guest_scope: InstrumentationScope::builder(GUEST_SCOPE).build(),
        }
    }
}

impl<E> fmt::Debug for Routed<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Routed").finish_non_exhaustive()
    }
}

type Entry<'a> = (&'a SdkLogRecord, &'a InstrumentationScope);

impl<E: LogExporter> LogExporter for Routed<E> {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let mut host: Vec<Entry> = Vec::new();
        let mut guests: Vec<(&InstrumentationScope, Vec<Entry>)> = Vec::new();
        for (record, scope) in batch.iter() {
            if scope.name() != GUEST_SCOPE {
                host.push((record, scope));
            } else if let Some((_, records)) = guests.iter_mut().find(|(s, _)| *s == scope) {
                records.push((record, &self.guest_scope));
            } else {
                guests.push((scope, vec![(record, &self.guest_scope)]));
            }
        }
        let mut inner = self.inner.lock().await;
        let mut result = Ok(());
        if !host.is_empty() {
            inner.set_resource(&self.host);
            result = inner.export(LogBatch::new(&host)).await;
        }
        for (scope, records) in guests {
            inner.set_resource(&Resource::builder_empty().with_attributes(scope.attributes().cloned()).build());
            // one guest failing shouldn't drop everyone else's records.
            result = result.and(inner.export(LogBatch::new(&records)).await);
        }
        result
    }

    fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> OTelSdkResult {
        // the processor only shuts its exporter down between exports, so the lock's free.
        self.inner.try_lock().map_or(Ok(()), |inner| inner.shutdown_with_timeout(timeout))
    }

    fn event_enabled(&self, level: opentelemetry::logs::Severity, target: &str, name: Option<&str>) -> bool {
        self.inner.try_lock().map_or(true, |inner| inner.event_enabled(level, target, name))
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.host = resource.clone();
        self.inner.get_mut().set_resource(resource);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _};

    use super::*;

    /// Keeps each record's body with the resource it exported under.
    #[derive(Debug, Default, Clone)]
    struct Capture {
        resource: Option<Resource>,
        exported: Arc<Mutex<Vec<(String, Resource, String)>>>,
    }

    impl LogExporter for Capture {
        fn export(&self, batch: LogBatch<'_>) -> impl Future<Output = OTelSdkResult> {
            let resource = self.resource.clone().unwrap();
            let mut exported = self.exported.lock().unwrap();
            for (record, scope) in batch.iter() {
                let body = match record.body() {
                    Some(AnyValue::String(s)) => s.to_string(),
                    other => panic!("{other:?}"),
                };
                exported.push((body, resource.clone(), scope.name().to_owned()));
            }
            std::future::ready(Ok(()))
        }

        fn set_resource(&mut self, resource: &Resource) {
            self.resource = Some(resource.clone());
        }
    }

    fn get(resource: &Resource, key: &'static str) -> Option<String> {
        resource.get(&opentelemetry::Key::from_static_str(key)).map(|v| v.to_string())
    }

    #[test]
    fn guest_records_export_under_their_own_resource() {
        let capture = Capture::default();
        let host = Resource::builder_empty()
            .with_attributes([
                KeyValue::new("service.name", "roost"),
                KeyValue::new("service.instance.id", "host-agent"),
                KeyValue::new("process.pid", 123),
                KeyValue::new("host.name", "testhost"),
            ])
            .build();
        let provider = SdkLoggerProvider::builder().with_resource(host.clone()).with_batch_exporter(Routed::new(capture.clone())).build();
        let guests = GuestLogs::new(provider.clone(), &host);
        let emit = |logger: &SdkLogger, body: &'static str| {
            let mut record = logger.create_log_record();
            record.set_body(body.into());
            logger.emit(record);
        };
        let web = guests.logger([KeyValue::new("container.name", "web"), KeyValue::new("service.instance.id", "web-id")]);
        let db = guests.logger([KeyValue::new("container.name", "db"), KeyValue::new("service.instance.id", "db-id")]);
        emit(&web, "from web");
        emit(&provider.logger("roost"), "from the host");
        emit(&db, "from db");
        emit(&web, "web again");
        provider.shutdown().unwrap();

        let exported = capture.exported.lock().unwrap();
        let by_body = |body: &str| exported.iter().find(|(b, ..)| b == body).unwrap_or_else(|| panic!("{body} wasn't exported"));
        let (_, resource, scope) = by_body("from web");
        assert_eq!(scope, GUEST_SCOPE, "guest scopes export without the resource they carry");
        assert_eq!(get(resource, "service.name").as_deref(), Some(GUEST_SCOPE));
        assert_eq!(get(resource, "service.instance.id").as_deref(), Some("web-id"), "the guest's attributes win");
        assert_eq!(get(resource, "container.name").as_deref(), Some("web"));
        assert_eq!(get(resource, "host.name").as_deref(), Some("testhost"), "guests inherit where they run");
        assert_eq!(get(resource, "process.pid"), None, "but not the host's process");
        assert_eq!(get(&by_body("web again").1, "container.name").as_deref(), Some("web"));
        assert_eq!(get(&by_body("from db").1, "container.name").as_deref(), Some("db"));
        let (_, resource, scope) = by_body("from the host");
        assert_eq!((get(resource, "service.name").as_deref(), scope.as_str()), (Some("roost"), "roost"));
        assert_eq!(get(resource, "process.pid").as_deref(), Some("123"));
    }
}
