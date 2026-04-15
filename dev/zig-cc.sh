#!/usr/bin/env bash
# C compiler for linting the Linux crates from a Mac. ring's build script compiles C for the Linux
# target, and zig ships that target's libc headers. cc-rs passes clang-style --target triples that
# zig can't parse, so we swap them for zig's own.
args=()
for arg in "$@"; do
  [[ $arg == --target=* ]] || args+=("$arg")
done
exec zig cc -target aarch64-linux-gnu "${args[@]}"
