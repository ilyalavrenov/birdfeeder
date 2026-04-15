# telemetry

roost and dispatcher export logs, traces and metrics with the OTel SDKs. guests send their logs and stats to roost over vsock, so they never need a route to a collector.

## configuration

the usual OTel env vars work: per-signal overrides, TLS, headers, `OTEL_*_EXPORTER=none`, `OTEL_SDK_DISABLED`, batching. with no endpoint set nothing gets exported, but JSON logs still go to stdout.

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf   # default grpc
OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=development
```

## guest logs

roost keeps one vsock stream open per running container, up to `guest_log_max_streams` (default 32, max 1024). records keep the guest's timestamp and get `service.name=birdfeeder.guest`, `container.name`, `container.id`, `log.iostream`, and `birdfeeder.{host.id,session.id,session.generation,template.id}`. `birdfeeder.log.gap=true` means some history was lost.

each stream is capped at 64 KiB/s with a 512 KiB burst. cursors move forward when the SDK enqueues a record and get checkpointed every second, so delivery is best-effort. a full queue drops records, and after a crash you can get repeats from the last checkpoint on. use `log.record.uid` to dedupe.

## metrics

custom instruments live under `birdfeeder.{firecracker,roost,dispatcher,vm,guest}.*` and are aggregated by `birdfeeder.template.id`, plus `birdfeeder.container.name` for containers. session IDs and claim labels are never dimensions. the custom names are made up for this project. they're not OTel semantic conventions.

guest stats get sampled every `metrics_interval_sec` (default 10), with a 1 s timeout per guest.

| instrument | measurement |
| --- | --- |
| `birdfeeder.guest.mem.total`, `.available` | guest memory, bytes |
| `birdfeeder.guest.mem.oom_kill` | OOM deltas between samples |
| `birdfeeder.guest.disk.used` | writable root disk, bytes |
| `birdfeeder.guest.container.mem.current` | container memory, bytes |
| `birdfeeder.guest.container.cpu.usage` | cores used between samples |
| `birdfeeder.guest.container.pids` | processes and threads |
| `birdfeeder.guest.container.oom_kills` | OOM deltas between samples |
| `birdfeeder.guest.stats.requests` | sampling attempts by outcome |

## local collector

`dev/collector/config.yaml` runs the pinned `otelcol` on 4317/4318 and writes rotating JSON files to `BIRDFEEDER_TELEMETRY_DIR`. `mise run test telemetry` checks every signal against it.
