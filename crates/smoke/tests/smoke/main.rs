//! Runs roost, the dispatcher and the CLI from bin/ against real guests. Each test needs root on an idle KVM host
//! that scripts/setup-linux.sh prepared, and all but `services` need the guest artifacts `dev/run-linux.sh artifacts`
//! builds. `mise run test smoke` runs them one at a time, `mise run test <suite>` runs one suite.
#![cfg(target_os = "linux")]

mod cli;
mod contract;
mod harness;
mod lifecycle;
mod registry;
mod snapshots;
mod telemetry;
mod workloads;

use contract::Snapshot;
use workloads::{Example, Scenario};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn services() {
    workloads::services().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn workloads_http() {
    workloads::run(Example::Http, Scenario::Plain).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn workloads_shared() {
    workloads::run(Example::Shared, Scenario::Plain).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn lifecycle() {
    workloads::run(Example::Http, Scenario::Lifecycle).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn telemetry() {
    workloads::run(Example::Shared, Scenario::Telemetry).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn registry() {
    registry::run().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn snapshots_eager() {
    snapshots::run(Snapshot::Eager).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root; see the crate docs"]
async fn snapshots_lazy() {
    snapshots::run(Snapshot::Lazy).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "boots guests as root for minutes; dev/run-linux.sh bench runs it"]
async fn bench_snapshots() {
    snapshots::bench().await;
}
