//! Stuff every birdfeeder service shares: OTel export configured from the environment, JSON logs on stdout, and gRPC
//! serving with tracing and a bounded graceful shutdown.

use std::{future::Future, process::ExitCode, time::Duration};

mod logging;
pub mod rpc;
pub mod telemetry;

const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(1);

/// Runs the future `main` makes on a multi-threaded runtime with telemetry installed, logs its error if it fails, and
/// flushes telemetry before returning the exit code.
pub fn run<F: Future<Output = anyhow::Result<()>>>(name: &'static str, main: impl FnOnce(&telemetry::Telemetry) -> F) -> ExitCode {
    // OTLP over HTTPS goes through reqwest's rustls, which uses the process's default provider. An error just means
    // one's already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("{name}: start the runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    // gRPC exporters set up their channels on whatever runtime they're built in.
    let telemetry = {
        let _entered = runtime.enter();
        telemetry::init(name)
    };
    let telemetry = match telemetry {
        Ok(telemetry) => telemetry,
        Err(err) => {
            eprintln!("{name}: telemetry: {err:#}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(main(&telemetry));
    if let Err(err) = &result {
        tracing::error!(error = format!("{err:#}"), "{name} exiting");
    }
    telemetry.shutdown();
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
    if result.is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
