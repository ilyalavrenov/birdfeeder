#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# root commands below get this PATH via sudo env, otherwise sudo's secure_path would clobber it.
export MISE_TRUSTED_CONFIG_PATHS=$PWD
mise install --quiet rust github:nextest-rs/nextest github:open-telemetry/opentelemetry-collector-releases github:seaweedfs/seaweedfs
eval "$(mise env -s bash)"

# suites below pick tests with -E filters, not -p or --test. building one target alone leaves out fcapigen,
# whose runtime syn shares proc-macro2 with the build scripts, and then everything above it rebuilds.

# a cargo target runner, so nextest builds the tests unprivileged and runs them as root. sudo drops the
# caller's env, so this passes PATH and any NAME=value args through. no spaces in those.
root_runner() {
  local triple
  triple=$(rustc -vV | sed -n 's/^host: //p')
  triple=${triple^^}
  echo "CARGO_TARGET_${triple//-/_}_RUNNER=sudo env PATH=$PATH $*"
}

build_commands() {
  mkdir -p bin
  # just the binaries installed below. the whole workspace would drag in fcapigen's codegen and a glibc init.
  cargo build --locked --release -p roost -p uffd-handler -p birdfeeder -p dispatcher
  install -m 0755 target/release/roost target/release/uffd-handler target/release/birdfeeder target/release/dispatcher bin/
}

# init and the test guest run in Alpine and in images with no libc, so they link musl statically. -p keeps
# the handler's TLS stack out of the build.
build_guest() {
  mkdir -p bin
  local target
  target=$(uname -m)-unknown-linux-musl
  cargo build --locked --release -p birdfeeder-init -p test-guest --target "$target"
  install -m 0755 "target/$target/release/birdfeeder-init" "target/$target/release/test-guest" bin/
}

# build-artifacts.sh packs the example bundle with birdfeeder pack.
build_artifacts() {
  build_commands
  build_guest
  sudo env PATH="$PATH" bash scripts/build-artifacts.sh "$PWD/bin/birdfeeder-init" "$PWD/bin/test-guest" "$PWD/bin/birdfeeder"
}

# Docker sets this policy and quietly drops guest egress we allowed, which the smoke checks need. it can
# be in either iptables backend, and both apply.
check_forward_policy() {
  for cmd in iptables iptables-legacy; do
    if command -v "$cmd" >/dev/null && sudo "$cmd" -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
      echo "$cmd FORWARD policy is DROP (Docker sets it), which blocks guest egress; run: sudo $cmd -P FORWARD ACCEPT" >&2
      exit 1
    fi
  done
}

build_smoke() {
  check_forward_policy
  build_commands
  # the registry suite packs the test guest into an image.
  build_guest
  # vm uids run the handler, so it lives next to firecracker, not under a private checkout.
  sudo install -m 0755 bin/uffd-handler /usr/local/bin/uffd-handler
}

run_smoke() {
  env "$(root_runner)" bash dev/nextest.sh "smoke-$1" -E "package(smoke) & test(/$2/)" --run-ignored only
}

# the vmm crate's KVM test covers restore modes roost never picks on its own, like a lazy restore with no
# recorded working set.
run_snapshot() {
  build_smoke
  run_smoke snapshot '^snapshots_'
  env "$(root_runner)" bash dev/nextest.sh vmm-kvm -E 'package(vmm) & binary(kvm)' --run-ignored only --no-capture
}

# built unprivileged, run as root. the forward-policy check needs root to read nftables.
host_check() {
  cargo build --locked --quiet -p hostcheck
  sudo target/debug/hostcheck
}

test_integration() {
  host_check
  bash dev/nextest.sh roost-host -E 'package(roost) & binary(host)' --run-ignored only
  env "$(root_runner)" bash dev/nextest.sh guestnet-root -E 'package(guestnet) & binary(root)' --run-ignored only
  AWS_ACCESS_KEY_ID=snapstore-test AWS_SECRET_ACCESS_KEY=snapstore-test-secret \
    bash dev/nextest.sh snapstore-weed -E 'package(snapstore) & binary(weed)' --run-ignored only
}

case "${1:-}" in
  deploy)
    build_commands
    sudo install -d /usr/local/libexec/birdfeeder
    for name in roost dispatcher uffd-handler; do
      sudo install -m 0755 "bin/$name" /usr/local/libexec/birdfeeder/
    done
    sudo install -m 0755 bin/birdfeeder /usr/local/bin/birdfeeder
    ;;
  # the codespace prebuild runs this so the first smoke run starts with warm cargo builds. cargo unifies
  # features across the packages it's given, so a whole-workspace build wouldn't get reused.
  build)
    build_commands
    build_guest
    ;;
  artifacts) build_artifacts ;;
  hostcheck) host_check ;;
  snapshot) run_snapshot ;;
  bench)
    build_smoke
    env "$(root_runner "BENCH_RUNS=${BENCH_RUNS:-10}")" bash dev/nextest.sh smoke-bench \
      -E 'package(smoke) & test(=bench_snapshots)' --run-ignored only --no-capture
    ;;
  services|workloads|lifecycle|telemetry|registry)
    build_smoke
    run_smoke "$1" "^$1"
    ;;
  test|linux)
    bash dev/nextest.sh unit
    if [[ "$1" == linux ]]; then test_integration; fi
    ;;
  integration) test_integration ;;
  smoke)
    build_smoke
    run_smoke services '^services$'
    build_artifacts
    run_smoke vms '^(workloads_|lifecycle$|telemetry$|registry$)'
    run_snapshot
    ;;
  *) echo 'usage: bash dev/run-linux.sh {build|deploy|hostcheck|linux|smoke|test|integration|services|artifacts|workloads|telemetry|lifecycle|registry|snapshot|bench}' >&2; exit 2 ;;
esac
