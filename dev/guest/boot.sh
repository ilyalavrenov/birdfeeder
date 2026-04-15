#!/bin/sh
set -eu
mount -t proc proc /proc
mount -t sysfs sysfs /sys
[ -c /dev/null ] || mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /run /sys/fs/cgroup
mount -t tmpfs -o mode=755,size=32m tmpfs /run
mount -t tmpfs -o mode=1777,size=32m tmpfs /tmp
# the root disk is shared and read-only, so per-guest state goes on the scratch disk.
mount -t ext4 /dev/vdb /var/lib/birdfeeder
mount -t cgroup2 cgroup2 /sys/fs/cgroup
mount --make-rprivate /
ip link set lo up
ip link set eth0 up
ip addr add 172.16.0.2/30 dev eth0
ip route add default via 172.16.0.1 dev eth0
ip route add 169.254.169.254 dev eth0
printf 'nameserver 172.16.0.1\n' > /run/resolv.conf
printf '127.0.0.1 localhost\n' > /run/hosts
