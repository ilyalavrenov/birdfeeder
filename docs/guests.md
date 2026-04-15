# guest images and workloads

## artifacts

`mise run dev artifacts` grabs a pinned guest kernel and builds the base disk and example image into `/var/lib/birdfeeder/artifacts`. paths and SHA-256s go in `artifacts.json`. every guest mounts the base disk read-only as root and gets its own copy of a 256 MiB scratch disk at `/var/lib/birdfeeder`. a rebuild changes the hashes, so you'll need new template IDs.

## image format

an image is a SquashFS of an OCI bundle (`config.json` + `rootfs/`). only process args, env, cwd and numeric uid/gid are used. hooks, devices, host paths and namespace paths get ignored. images mount `nodev`.

```sh
birdfeeder pack ./bundle image.squashfs                 # an unpacked, trusted bundle
birdfeeder convert python:3.13-slim python.squashfs     # a registry image (Linux, squashfs-tools 4.6+)
```

`convert` pulls for the host's architecture (`--platform` changes that) using `~/.docker/config.json` credentials. it flattens layers straight into `mksquashfs` and looks up user names in the image's own `/etc/passwd`. the same digest always gives the same output. images with no entrypoint still convert, but then the template's `args` has to provide one.

## manifests

see [the HTTP example](../examples/http.json) and [the shared-volume example](../examples/shared.json).

- up to 16 containers, volumes and readiness probes (TCP or vsock). the whole manifest can be at most 32 KiB.
- manifest args replace the image's. env gets merged on top of the image's. volumes are root-owned directories shared by whichever containers mount them.
- containers start at the same time and share the VM's network. each gets its own PID, mount, IPC, UTS and cgroup namespaces. the real isolation boundary is the VM. limits are 256 processes, 1024 fds and a fixed set of capabilities.
- if any container exits, the VM powers off and the pool refills.

## vsock agent (port 5000)

| request | reply |
| --- | --- |
| `LOGS <container> <after_seq>` | JSONL records after `after_seq`, then follows; `gap: true` after lost history |
| `STATS 1` | one JSON snapshot of guest and per-container cgroup counters |
| `CLOCK 1 <unix_nanos>` | sets the wall clock after a restore; `OK` |

logs rotate at 1 MiB, long lines get split at 64 KiB, and the agent handles at most 32 clients. more in [telemetry](telemetry.md).
