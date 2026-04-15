#!/usr/bin/env bash
# prepares the codespace container for roost on every start; run as root.
set -euo pipefail

# cgroup v2 lets a non-root cgroup enable controllers for children only when it holds no processes,
# so move the container's processes into a leaf before roost creates /sys/fs/cgroup/birdfeeder.
# the codespace agent keeps exec'ing into the root, so retry until a pass leaves it empty.
mkdir -p /sys/fs/cgroup/init
controllers=$(sed -e 's/ / +/g' -e 's/^/+/' /sys/fs/cgroup/cgroup.controllers)
for _ in $(seq 50); do
  while read -r pid; do
    echo "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
  done < /sys/fs/cgroup/cgroup.procs
  if echo "$controllers" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [[ $(< /sys/fs/cgroup/cgroup.subtree_control) != "$(< /sys/fs/cgroup/cgroup.controllers)" ]]; then
  echo 'could not delegate cgroup controllers; processes keep landing in the container root' >&2
  exit 1
fi

# the container shares the codespace VM's network namespace, whose Docker sets a legacy iptables
# FORWARD DROP policy that silently blocks guest egress.
if command -v iptables-legacy >/dev/null; then
  iptables-legacy -P FORWARD ACCEPT
fi
