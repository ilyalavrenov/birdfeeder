# deploying

roost and dispatcher are just long-running processes that log JSON to stdout. any supervisor will do:

```sh
roost --config /etc/birdfeeder/roost.json
BIRDFEEDER_HOSTS=127.0.0.1:7443 dispatcher
```

guests outlive roost, so the supervisor has to:

- run roost as root on a dedicated host. a default-drop FORWARD policy (Docker sets one) breaks guest networking. `cargo run -p hostcheck` checks for that, and for KVM.
- keep `run_dir` (`/run/birdfeeder`) around across roost restarts.
- signal only roost. Firecracker and its uffd handlers run in their own sessions and cgroups, so a SIGTERM or SIGKILL to roost leaves them running. tearing down a PID namespace (like `docker stop` does) takes them down too.
- restart roost after a crash. the new one adopts the live VMs.

the dispatcher doesn't keep any state.

to retire a host, set its pool targets to zero, restart roost, then delete every session:

```sh
birdfeeder --server 127.0.0.1:7443 rm $(birdfeeder --server 127.0.0.1:7443 ls -o name)
```

API authentication isn't implemented yet, so stick to the default loopback bindings or a trusted network.
