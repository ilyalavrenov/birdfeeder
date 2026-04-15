#!/usr/bin/env bash
set -euo pipefail
# Firecracker's CI publishes guest kernels built from its microvm config but no checksums, so we pin
# the hashes here. bump all four together from a newer firecracker-ci/<date>-<commit> folder.
kernel_set=20261028-84df49062576-0
linux_version=6.18.56
bf_out=${1:?output directory required}
mkdir -p "$bf_out"
case "$(uname -m)" in
  aarch64) bf_arch=aarch64 bf_sha256=ba2081f71b3405e7f7be606b849b5341d2272dcb79999cb67f8061e711d0883f ;;
  x86_64) bf_arch=x86_64 bf_sha256=a00c1f68304e83ae4e0b5afe88972ad23fda52ed1a40335611aa18faa95d1b10 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [[ -f "$bf_out/kernel" ]] && printf '%s  %s\n' "$bf_sha256" "$bf_out/kernel" | sha256sum -c --quiet - 2>/dev/null; then
  echo 'kernel is up to date'
  exit 0
fi
curl -fsSL --retry 3 "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$kernel_set/$bf_arch/vmlinux-$linux_version" -o "$bf_out/kernel.tmp"
printf '%s  %s\n' "$bf_sha256" "$bf_out/kernel.tmp" | sha256sum -c --quiet -
chmod 0644 "$bf_out/kernel.tmp"
mv "$bf_out/kernel.tmp" "$bf_out/kernel"
