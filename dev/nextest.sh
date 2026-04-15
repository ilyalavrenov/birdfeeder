#!/usr/bin/env bash
# cargo nextest run, then copies the JUnit report to target/nextest/reports/<name>.xml. every run
# overwrites its profile's junit.xml, and CI's test report wants one per suite.
set -euo pipefail
name=$1
shift
junit=target/nextest/${NEXTEST_PROFILE:-default}/junit.xml
rm -f "$junit"
status=0
cargo nextest run --locked "$@" || status=$?
if [[ -f $junit ]]; then
  mkdir -p target/nextest/reports
  cp "$junit" "target/nextest/reports/$name.xml"
fi
exit "$status"
