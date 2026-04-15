use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let args = roost::Args::parse();
    service::run("roost", |telemetry| roost::run(args, telemetry.guest_logs().cloned()))
}
