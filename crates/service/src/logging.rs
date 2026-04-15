//! One JSON object per event on stdout, carrying the active trace and span ids so a log line leads to its trace.

use std::{fmt, io};

use opentelemetry::trace::TraceContextExt as _;
use serde_json::{Map, Value};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    fmt::{
        FmtContext, FormatEvent, FormatFields, Layer,
        format::Writer,
        time::{FormatTime as _, SystemTime},
    },
    registry::LookupSpan,
};

pub(crate) fn layer<S>() -> Layer<S, tracing_subscriber::fmt::format::DefaultFields, Json, fn() -> io::Stdout>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer().event_format(Json).with_writer(io::stdout as fn() -> io::Stdout)
}

pub(crate) struct Json;

impl<S, N> FormatEvent<S, N> for Json
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, _: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        writeln!(writer, "{}", Value::Object(record(event)))
    }
}

fn record(event: &Event<'_>) -> Map<String, Value> {
    let mut time = String::new();
    // SystemTime only fails if the writer does, and a String never does.
    let _ = SystemTime.format_time(&mut Writer::new(&mut time));
    let meta = event.metadata();
    let mut out = Map::new();
    out.insert("timestamp".into(), time.into());
    out.insert("level".into(), meta.level().as_str().into());
    out.insert("target".into(), meta.target().into());
    event.record(&mut Fields(&mut out));
    // the OTel layer activates a span's context while the span is entered.
    let cx = opentelemetry::Context::current();
    let span = cx.span();
    let ids = span.span_context();
    if ids.is_valid() {
        out.insert("trace_id".into(), ids.trace_id().to_string().into());
        out.insert("span_id".into(), ids.span_id().to_string().into());
    }
    out
}

struct Fields<'a>(&'a mut Map<String, Value>);

impl Visit for Fields<'_> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0.insert(field.name().into(), value.to_string().into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}").into());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt as _};

    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = Self;

        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[test]
    fn events_carry_fields_and_trace_ids() {
        let buffer = Buffer::default();
        let tracer = SdkTracerProvider::builder().build().tracer("test");
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .with(tracing_subscriber::fmt::layer().event_format(Json).with_writer(buffer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(host = "wa", attempts = 2_u64, "outside a span");
            tracing::info_span!("rpc").in_scope(|| tracing::warn!(error = %io::Error::other("boom"), "inside"));
        });
        let out = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["message"], "outside a span");
        assert_eq!(lines[0]["host"], "wa");
        assert_eq!(lines[0]["attempts"], 2);
        assert_eq!(lines[0]["level"], "INFO");
        assert!(lines[0].get("trace_id").is_none());
        assert_eq!(lines[1]["error"], "boom");
        assert_eq!(lines[1]["trace_id"].as_str().unwrap().len(), 32);
        assert_eq!(lines[1]["span_id"].as_str().unwrap().len(), 16);
        assert!(lines[1]["timestamp"].as_str().unwrap().ends_with('Z'));
    }
}
