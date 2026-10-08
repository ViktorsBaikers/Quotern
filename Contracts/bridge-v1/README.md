# Bridge v1 contract

The Rust core (`quotern-ffi`, a static library) and the Swift client (`QuoternCore`) share
these goldens. Rust serializes them from the real exports and Swift decodes them; neither
side retypes an expectation. A header, DTO or golden change lands with both consumers.

| File | Meaning |
| --- | --- |
| `requests-first-use.json` | One request per first-use call. Swift encodes these exact objects; Rust parses them through the real exports. |
| `open-ok.json`, `sources-list.json` | Responses of `quotern_engine_open` and `ingest`. |
| `snapshot-*.json` | `today_snapshot` responses: empty, acquired OpenCode counters, catching up, pending partial. |
| `error-*.json` | The fixed error envelopes. Each equals the code, message and retryable table below. |

Integers keep their Rust widths: token values and record counts are `UInt64`, `*_ms` are
`Int64` in `0..=253402300799999`, pass counters are `UInt32`. A `null` observation means
unknown, never zero.

## Data directory

`data_dir` is an explicit, app-owned directory. For development and tests use a fresh,
isolated directory that you never create yourself: the first valid source selection creates
it. A directory written by an earlier unshipped V1 shape returns `store_corrupt` and stays
byte-unchanged; the recovery is a new directory. History is never deleted.

### First attach returns `store_corrupt` and no history exists

A first `set_source_selection` that fails before any history exists (for example the parent
of `data_dir` is not writable, or an alias of it is unsafe) returns the same fixed envelope
as a damaged store: `store_corrupt`, `store corrupt`, not retryable. The envelope does not
tell the causes apart. Check access to the parent of `data_dir` and that no component is an
unsafe alias, then correct it, or close the client and open a fresh isolated `data_dir`.
Never delete a history to recover.

## Errors

| Code | Message | Retryable | Recovery |
| --- | --- | --- | --- |
| `invalid_request` | `invalid request: <field>` | no | fix the request |
| `unknown_method` | `unknown method` | no | fix the caller |
| `limit_exceeded` | `limit exceeded: <bound>` | no | see below |
| `cancelled` | `cancelled` | yes | call `ingest` again; groups completed before the poll stay published |
| `source_unavailable` | `source unavailable: <source_id> <failure_code>` | yes | the next trigger; no SLICE-001 method emits it, per-source failures are `SourceEntry` data |
| `source_overlap_conflict` | `source overlap conflict` | no | pick a root disjoint from the data directory and other roots |
| `store_busy` | `store busy` | yes | repeat; another native owner holds the data directory |
| `store_corrupt` | `store corrupt` | no | store error view; never delete |
| `store_newer_version` | `store newer version` | no | use the newer app |
| `store_migration_failed` | `store migration failed` | yes | close, then open |
| `internal_panic` | `internal panic` | no | `reopen()`; the failed request is not re-sent |
| `engine_failed` | `engine failed` | no | `reopen()`; never repeat on that handle |

Rust never emits the two client-only codes:

- `abi_mismatch` (`incompatible engine`, not retryable): `quotern_abi_version()` is not 1.
  `open` was never called. Recovery: a matching build.
- `malformed_response` (`malformed response`, not retryable): a returned string was not
  UTF-8, not a v1 envelope, or did not decode into its DTO. The string was freed once first.
  The caller keeps its last good value and may `reopen()` once; nothing is substituted.

### `limit_exceeded` recovery by bound

The code, message and retryable flag never change; the bound in the message selects the
recovery.

- `config_bytes`, `method_bytes`, `request_bytes`, `response_bytes`, `store_limit`: narrow
  the request.
- `admission_wal_bytes`: close every native handle on that data directory, bring `-wal`
  within 64 MiB with an outside or offline checkpoint, then open again.
- `admission_read_bytes`, `enabled_sources`: no in-app or guaranteed outside recovery; the
  store stays unavailable and history is never deleted.

## First success

`testFirstUseExample` runs the two blocks below verbatim: its marked setup and calls regions
equal them after indentation removal. The setup declares every name with sanitized values.
`Support` and `WalWriter` are the test-support types of
`Tests/QuoternCoreTests/BridgeRoundTripTests.swift`; `WalWriter` is a controlled
`/usr/bin/sqlite3` writer child (stdin piped, not in-process) that applies
`Fixtures/harness/opencode/wal/schema.sql` and `Fixtures/harness/opencode/daily/rows.json` in
WAL mode and stays open, so `-wal` and `-shm` exist through `ingest`. `t` and `z` are the
`now_ms` and `tz` of the `utc_counters` case of `Fixtures/harness/opencode/daily/expected.json`.

```swift
let base = try Support.canonicalTemporaryDirectory()  // a fresh temporary directory
let d = base.appendingPathComponent("data").path      // absent; the caller never creates it
let h = base.appendingPathComponent("home").path      // created empty
let r = base.appendingPathComponent("opencode").path  // the sanitized daily fixture source
let t: Int64 = 1_775_124_000_000                      // now_ms of utc_counters
let z = "UTC"                                         // tz of utc_counters
try FileManager.default.createDirectory(atPath: h, withIntermediateDirectories: false)
try FileManager.default.createDirectory(atPath: r, withIntermediateDirectories: false)
let writer = try WalWriter(database: r + "/opencode.db", rows: Support.dailyRows())
defer {
    writer.quit()
    Support.remove(base)
}
```

The calls:

```swift
func firstUse(_ r: String) async throws -> TodaySnapshot {
    let c = EngineClient()
    do {
        try await c.open(.init(dataDir: d, home: h))
        _ = try await c.setSourceSelection(.init(harness: "opencode", root: r, selected: true))
        _ = try await c.ingest(nowMs: t)
        let s = try await c.todaySnapshot(tz: z, nowMs: t)
        await c.close()
        return s
    } catch {
        await c.close()
        throw error
    }
}
```

`firstUse(r)` returns `s` whose `sourceReported` equals that case's oracle, with the writer
still running; afterwards the writer exits 0 and every opened handle is closed. A relative `r`
throws `invalid_request` and the handle is still closed. The example holds no user path,
credential or real usage data.

`source_idle` is a file state, not writer liveness: a WAL-mode source whose `-wal`, `-shm`
and `-journal` are all absent at `ingest` (the SLICE-004 S2 state) gives `source_idle` for
that source, never the oracle. A stopped writer that keeps valid sidecars (for example macOS
`/usr/bin/sqlite3` after `.quit`) is S3-class and is not required to give `source_idle`.
