# runtime contracts

## services

`roost --config roost.json` runs on one Linux/KVM host and assumes it has the box to itself. unknown config fields make it refuse to start. `dispatcher` spreads session RPCs over the `host:port` list in `BIRDFEEDER_HOSTS` (up to 128). both listen on loopback by default (roost 7443, dispatcher 8080) and talk h2c. `dispatcher --help` shows its timing flags.

give `session_state_dir` its own small filesystem. claims fsync it, and on ext4 with `data=ordered` that fsync ends up waiting on guest disk writeback if they share a journal.

## templates and admission

a template pins its kernel, disks and blobs by SHA-256, and roost checks them before boot. the fingerprint covers everything except paths and `pool_target`, so if you change a definition you need a new `template_id`.

| setting | default |
| --- | --- |
| `max_sessions`, `max_vcpus`, `max_memory_mib` | 2, 2, 1024 |
| template `vcpus`, `mem_mib`, `pool_target` | 1, 512, 0 |

each VM reserves everything it asks for, and the warm targets have to fit in the budget.

## snapshots

with `snapshot: "eager"` or `"lazy"`, a pool restores guests from one guest's memory instead of booting them. the first boot after roost starts is a cold boot that takes the snapshot. after that, boots are restores. `lazy` serves pages on fault through `uffd-handler`. its first restore records which pages get touched during readiness and the `snapshot_warmup` GETs, and later restores prefetch those. after three failed restores in a row the pool goes back to cold boots until roost restarts.

if you set `snapshot_store` (`endpoint`, `region`, `bucket`, optional `prefix`, `path_style`, `presign_ttl_sec`), roost uploads each snapshot's memory, a manifest of its non-zero pages, and the packed working set. restores pull them with presigned GETs and never fetch zero pages. credentials come from the AWS SDK default chain. roost never deletes old objects, so set a lifecycle rule on the bucket.

restores hardlink the snapshot into each nest, so `state_dir` and `jailer.chroot_base` have to be on the same filesystem. after a restore, roost resets the guest clock over vsock and VMGenID reseeds the guest's RNG.

## claims and retries

the API is `birdfeeder.roost.v1.RoostService` ([proto](../api/roost/v1/roost.proto)) over gRPC. any client works, e.g.

```sh
buf curl --protocol grpc --http2-prior-knowledge --schema api/roost/v1/roost.proto \
  http://127.0.0.1:8080/birdfeeder.roost.v1.RoostService/ClaimSession \
  -d '{"templateId": "agent-sandbox-v1", "egress": {"fqdnAllowlist": ["pypi.org"]}, "idleTimeoutMs": 900000}'
```

- a claim grabs a ready guest from the pool for that exact `template_id`. if the pool's empty you get `resource_exhausted`. nothing boots on demand.
- you set labels (max 32), egress (max 128 entries per list) and `idle_timeout_ms` (max 7 days, 0 turns it off) when you claim.
- the dispatcher only tries another host after `resource_exhausted`. a timeout or `unavailable` could mean the claim went through, so it doesn't retry those.
- with an `idempotency_key` (max 128 bytes) any claim is safe to retry. same key and same request gets you the same session. same key with a different request is `failed_precondition`. keys stick around for `claim_key_retention_sec` (default 1 day) after the session's deleted.
- `DeleteSession` and `SetSessionExpiry` need the claim's generation, so a stale call can't hit a newer session.
- the CLI exits 5 when no guest is ready and 6 when it can't tell whether a claim happened.

## networking

- egress is blocked unless the claim's CIDR or FQDN allowlist lets it through. `0.0.0.0/0` opens up the internet.
- metadata, link-local and guest-to-guest traffic are always blocked. SMTP is blocked unless you turn it on.
- FQDN rules go through a DNS proxy on the host. a DNS answer can't open up private, metadata or SMTP destinations.
- pooled guests have no egress until they're claimed, so anything needed at boot has to be in the image.
- up to 16 named TCP endpoints map guest ports to host ports. they're only published while the session is claimed.
