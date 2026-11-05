#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux || $EUID != 0 ]]; then
  echo 'run setup-linux.sh as root on a Debian or Ubuntu Linux host' >&2
  exit 1
fi
# --install-only skips the checks and grants that need the host's devices, so a codespace prebuild
# can run it. postCreateCommand runs the full script on the real host. Rust and the other dev tools
# come from mise.toml.
install_only=false
[[ ${1:-} == --install-only ]] && install_only=true
cd "$(dirname "$0")/.."

# renovate: datasource=github-releases depName=jdx/mise
mise_version=v2026.11.0
# renovate: datasource=github-releases depName=firecracker-microvm/firecracker
firecracker_version=v1.17.0
arch=$(uname -m)
case "$arch" in
  aarch64) mise_arch=arm64 ;;
  x86_64) mise_arch=x64 ;;
  *) echo 'unsupported host architecture' >&2; exit 1 ;;
esac

# ring's build script and Rust's linker need gcc and libc6-dev. CI images already have everything,
# so checking first lets us skip apt-get update there.
packages=(ca-certificates curl nftables iproute2 acl e2fsprogs squashfs-tools gcc libc6-dev)
if ! status=$(dpkg-query -W -f='${db:Status-Abbrev}\n' "${packages[@]}" 2>/dev/null) || grep -qv '^ii' <<<"$status"; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq "${packages[@]}"
fi

if ! $install_only; then
  test -e /sys/fs/cgroup/cgroup.controllers
  test -c /dev/kvm
  test -c /dev/net/tun
fi

work=$(mktemp -d /var/tmp/birdfeeder-setup.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
# any mise on PATH at the pinned version works, like the one mise-action puts there in CI.
if [[ $(mise --version 2>/dev/null) != "${mise_version#v} "* ]]; then
  release=https://github.com/jdx/mise/releases/download/$mise_version
  bash scripts/fetch-release.sh "$release/mise-$mise_version-linux-$mise_arch" "$release/SHASUMS256.txt" "$work/mise"
  install -m 0755 "$work/mise" /usr/local/bin/mise
fi
if [[ $(/usr/local/bin/firecracker --version 2>/dev/null | head -n 1) != "Firecracker $firecracker_version" ]]; then
  asset=https://github.com/firecracker-microvm/firecracker/releases/download/$firecracker_version/firecracker-$firecracker_version-$arch.tgz
  bash scripts/fetch-release.sh "$asset" "$asset.sha256.txt" "$work/firecracker.tgz"
  tar -xzf "$work/firecracker.tgz" -C "$work"
  for bin in firecracker jailer; do
    install -m 0755 "$work/release-$firecracker_version-$arch/$bin-$firecracker_version-$arch" "/usr/local/bin/$bin"
  done
fi
install -d -m 0755 /var/lib/birdfeeder
if $install_only; then
  exit 0
fi

if [[ -n ${SUDO_USER:-} ]]; then
  setfacl -m "u:$SUDO_USER:rw" /dev/kvm
fi
/usr/local/bin/firecracker --version
echo 'next, as the development user: mise install && bash dev/run-linux.sh hostcheck'
