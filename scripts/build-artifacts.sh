#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# renovate: datasource=endoflife-date depName=alpine-linux
alpine_version=3.23.4
# renovate: datasource=github-releases depName=opencontainers/runc
runc_version=v1.4.2
bf_init=$(realpath "${1:?birdfeeder-init binary required}")
bf_http=$(realpath "${2:?test guest binary required}")
bf_cli=$(realpath "${3:?birdfeeder binary required}")
bf_out=${4:-/var/lib/birdfeeder/artifacts}
mkdir -p "$bf_out"
bf_out=$(realpath "$bf_out")
exec 9>"$bf_out/build.lock"
flock -n 9 || { echo 'another artifact build is running' >&2; exit 1; }
if ! dpkg-query -W -f='${db:Status-Abbrev}' squashfs-tools 2>/dev/null | grep -q '^ii'; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y squashfs-tools
fi
bash scripts/fetch-kernel.sh "$bf_out"
bf_arch=$(uname -m)
bf_stage=$(mktemp -d "$bf_out/build.XXXXXXXX")
trap 'rm -rf -- "$bf_stage"' EXIT
bf_alpine=https://dl-cdn.alpinelinux.org/alpine/v${alpine_version%.*}/releases/$bf_arch/alpine-minirootfs-$alpine_version-$bf_arch.tar.gz
bash scripts/fetch-release.sh "$bf_alpine" "$bf_alpine.sha256" "$bf_stage/alpine.tar.gz"
case "$bf_arch" in
  aarch64) runc_asset=runc.arm64 ;;
  x86_64) runc_asset=runc.amd64 ;;
esac
bf_runc=https://github.com/opencontainers/runc/releases/download/$runc_version
bash scripts/fetch-release.sh "$bf_runc/$runc_asset" "$bf_runc/runc.sha256sum" "$bf_stage/runc"
mkdir -p "$bf_stage/base" "$bf_stage/bundle/rootfs"
tar -xzf "$bf_stage/alpine.tar.gz" -C "$bf_stage/base"
tar -xzf "$bf_stage/alpine.tar.gz" -C "$bf_stage/bundle/rootfs"
install -D -m 0755 "$bf_init" "$bf_stage/base/usr/local/bin/birdfeeder-init"
install -D -m 0755 "$bf_stage/runc" "$bf_stage/base/usr/local/bin/runc"
install -D -m 0755 dev/guest/boot.sh "$bf_stage/base/etc/birdfeeder-boot"
# root is mounted read-only, so boot.sh writes these under /run.
ln -sfn /run/resolv.conf "$bf_stage/base/etc/resolv.conf"
ln -sfn /run/hosts "$bf_stage/base/etc/hosts"
mkdir -p "$bf_stage/base/var/lib/birdfeeder"
cat > "$bf_stage/base/etc/inittab" <<'INITTAB'
::sysinit:/etc/birdfeeder-boot
::once:/etc/birdfeeder-run
::shutdown:/bin/umount -a -r
INITTAB
cat > "$bf_stage/base/etc/birdfeeder-run" <<'RUN'
#!/bin/sh
/usr/local/bin/birdfeeder-init
sync
# firecracker exits on a guest reboot on every arch. an x86 guest can't power off, it just halts.
reboot -f
RUN
chmod 0755 "$bf_stage/base/etc/birdfeeder-run"
install -D -m 0755 "$bf_http" "$bf_stage/bundle/rootfs/usr/local/bin/serve"
mkdir -p "$bf_stage/bundle/rootfs/srv"
printf 'hello from birdfeeder\n' > "$bf_stage/bundle/rootfs/srv/index.html"
cat > "$bf_stage/bundle/config.json" <<'JSON'
{"ociVersion":"1.3.0","root":{"path":"rootfs"},"process":{"args":["/usr/local/bin/serve","--listen","0.0.0.0:8080","--root","/srv"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"cwd":"/","user":{"uid":0,"gid":0}}}
JSON
"$bf_cli" pack "$bf_stage/bundle" "$bf_stage/alpine.squashfs"
truncate -s 256M "$bf_stage/base.ext4"
mkfs.ext4 -q -F -m 0 -d "$bf_stage/base" "$bf_stage/base.ext4"
truncate -s 256M "$bf_stage/scratch.ext4"
mkfs.ext4 -q -F -m 0 "$bf_stage/scratch.ext4"
# publish the artifact files before writing the manifest that points at their hashes.
mv "$bf_stage/base.ext4" "$bf_out/base.ext4"
mv "$bf_stage/scratch.ext4" "$bf_out/scratch.ext4"
mv "$bf_stage/alpine.squashfs" "$bf_out/alpine.squashfs"
bf_manifest=$bf_out/artifacts.json
{
  printf '{'
  sep=
  for name in kernel base.ext4 scratch.ext4 alpine.squashfs; do
    sum=$(sha256sum "$bf_out/$name" | cut -d' ' -f1)
    printf '%s\n  "%s": {"path": "%s", "sha256": "%s"}' "$sep" "$name" "$bf_out/$name" "$sum"
    sep=,
  done
  printf '\n}\n'
} > "$bf_manifest.tmp"
chmod 0644 "$bf_manifest.tmp"
mv "$bf_manifest.tmp" "$bf_manifest"
cat "$bf_manifest"
