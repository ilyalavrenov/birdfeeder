use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let config = dispatcher::Config::parse();
    service::run("dispatcher", |_| dispatcher::run(config))
}
