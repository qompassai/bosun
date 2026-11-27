# Benchmarks — bosun

Measured 2026-11-27 (batch B1) on primo: 13th Gen Intel Core i7-13620H,
16 threads, 62 GiB RAM, cargo/rustc 1.100.0. The bench harness
(`benches/hot_paths.rs`, hand-rolled on `std::time`, `harness = false`)
drives the **debug** server binary over stdio; numbers are single-run
and primo is a shared machine, so treat them as orientation, not
lab-grade. Reproduce with:

```sh
cargo build --examples --benches
cargo bench --bench hot_paths
cargo run --example stdio_session   # the session the bench drives
```

## Workloads

| Workload | Definition |
| --- | --- |
| `cold_start_discover` | Spawn the server, send `server/discover` (modern era 2026-07-28), await the response; averaged over 5 spawns. |
| `tools_list` | `tools/list` on a warm session; 20 warmup calls, then 200 measured calls. |
| `tool_call` | Representative read-only call `bosun_device_list` on a warm session; 20 warmup calls, then 200 measured calls. |

Session setup: `BOSUN_HOME` points at a temp dir, so the inventory starts empty.

Tool surface seen by the example: 12 tools (bosun_device_list, bosun_device_get, bosun_gate_check, ...).

## Results (2026-11-27 run)

| Workload | Result |
| --- | --- |
| cold start → discover | 30.04 ms per spawn (avg of 5) |
| tools/list | 7,980,047 ns/op (125.3 ops/s) |
| tools/call `bosun_device_list` | 4,272,339 ns/op (234.1 ops/s) |

## Gates at the same commit

- `cargo build --examples` — clean
- `cargo run --example stdio_session` — green (`stdio_session: ok`)
- `cargo bench --bench hot_paths` — runs to the numbers above
- `cargo test` — 75 passed, 0 failed
- `cargo clippy --examples --benches` — no errors or warnings on the added files

Base commit: `79123dd` (main). Branch: `pax/benchmarks-examples-20261127`.
