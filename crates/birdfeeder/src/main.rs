use std::process::ExitCode;

use birdfeeder::cli;

fn main() -> ExitCode {
    // registry pulls go through reqwest's rustls, which uses the process-wide default provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("birdfeeder: start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    let env = cli::Env {
        stdout: &mut stdout,
        stderr: &mut stderr,
        server: std::env::var(cli::SERVER_ENV).ok(),
        now: chrono::Local::now().fixed_offset(),
    };
    runtime.block_on(cli::run(std::env::args_os(), env))
}
