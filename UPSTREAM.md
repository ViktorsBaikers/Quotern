# Upstream sources and fixture provenance

## SQLite

The project uses `rusqlite` with its bundled SQLite build. The linked library identity was captured by `sqlite_version_is_recorded` on the locked target:

- SQLite version: `3.53.2`
- SQLite source ID: `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`

The runtime probe, not a package-version assumption, is the source of these values. The read-only WAL implementation was checked against SQLite's [WAL documentation, section 5](https://www.sqlite.org/wal.html#readonly) and [`sqlite3_open` URI documentation](https://www.sqlite.org/c3ref/open.html). Documentation alone does not establish that an open has no side effects; `opencode_wal` contains the child-writer, live-WAL, crash, locking, hot-journal, sidecar, and VFS mutation proofs for the linked build.

In the locked `libsqlite3-sys` 0.38.2 source, `sqlite3/sqlite3.c:45219-45230` skips the `O_RDWR|O_CREAT` shared-memory open when `readonly_shm` is set and falls back to a read-only open. At line 45423 the VFS returns `SQLITE_READONLY` for a read-only shared-memory mapping. However, the same source (`sqlite3.c:45153-45160`) reuses an existing `-shm` node inside the process, so a same-process writer's writable mapping can be handed to a read-only connection.

Quotern therefore registers its own `quotern-ro` VFS, which wraps SQLite's Unix VFS: write-capable open flags are stripped, every descriptor is verified to be a regular, effectively read-only file, and a shared-memory mapping is accepted only when its protection is observed read-only. A writable or unverifiable mapping (for example a writer connection in the same process) fails closed and the source is reported unavailable instead of being read. Live WAL acquisition is therefore positive only for writers in another process; `opencode_wal` covers both outcomes with VFS counters, byte-for-byte source images, and WAL permission-mode/owner checks (`empty_wal_mode_mismatch_is_not_changed_by_acquisition`). The runtime matrix, not this note, is the behavior proof for this bundled build.

## Data directory ownership

One native owner per app data directory is a `flock(LOCK_EX|LOCK_NB)` on the held directory descriptor, declared through an `extern "C"` block against the system `libc` (no added dependency). It is advisory: it excludes another Quotern owner, not an arbitrary outside writer. Admission of an existing history is therefore a bounded, effect-free committed read followed by a byte-exact recheck; `admission_outside_writer_windows_are_unsupported` records four windows (a write between the log walk and the view read, a torn tail completed after admission, an earlier commit checksum rewritten, a main-file write after its range was compared) that the recheck cannot see. They are documented limits, not refusals.

## OpenCode format references

These pinned source snapshots were used for bounded source-level comparison. The upstream projects were not executed, and no live OpenCode account or database was accessed.

| Project | Revision | Source references | Use |
| --- | --- | --- | --- |
| [CodexBar](https://github.com/steipete/CodexBar/tree/3239175f6a43aff35a52abc9072f8eca69444a7d) | `3239175f6a43aff35a52abc9072f8eca69444a7d` | [OpenCode Go local reader](https://github.com/steipete/CodexBar/blob/3239175f6a43aff35a52abc9072f8eca69444a7d/Sources/CodexBarCore/Providers/OpenCodeGo/OpenCodeGoLocalUsageReader.swift), [reader tests](https://github.com/steipete/CodexBar/blob/3239175f6a43aff35a52abc9072f8eca69444a7d/Tests/CodexBarTests/OpenCodeGoLocalUsageReaderTests.swift) | Comparison for local reported-token fields and fixture convention naming. |
| [CodeBurn](https://github.com/getagentseal/codeburn/tree/986d72ce1efbfaf40b3c9d4050d9ecdbc24be986) | `986d72ce1efbfaf40b3c9d4050d9ecdbc24be986` | [OpenCode SQLite session parser](https://github.com/getagentseal/codeburn/blob/986d72ce1efbfaf40b3c9d4050d9ecdbc24be986/src/providers/sqlite-session-parser.ts), [JSON message parser](https://github.com/getagentseal/codeburn/blob/986d72ce1efbfaf40b3c9d4050d9ecdbc24be986/src/providers/opencode-file-parser.ts) | Comparison for OpenCode SQLite and JSON storage layouts. |
| [QuotaBar](https://github.com/QuotaBar/QuotaBar/tree/a96f8dc42c41dbae22ee1ddccad4f3e4678b4b74) | `a96f8dc42c41dbae22ee1ddccad4f3e4678b4b74` | [SQLite reader](https://github.com/QuotaBar/QuotaBar/blob/a96f8dc42c41dbae22ee1ddccad4f3e4678b4b74/Sources/QuotaCore/SQLiteRead.swift), [usage reader](https://github.com/QuotaBar/QuotaBar/blob/a96f8dc42c41dbae22ee1ddccad4f3e4678b4b74/Sources/QuotaCore/Cost.swift) | Comparison for local session aggregation and SQLite opening behavior. |

The peer-derived total convention is named `codexbar-3239175f-disjoint`. It is used only when all five reported components are present and the source record has no explicit total. The peer fixtures store expected values independently of the adapter.

## Codex record contract

Codex usage is acquired as source-reported tokens with an "origin unverified" label (DEC-077); it is never measured, provider-verified or pooled across sources. The adapter (`crates/quotern-core/src/adapters/codex.rs`) is a redesign against the producer's persisted record contract, not a port: no upstream code was copied, and the cumulative `token_count` delta approach of other readers is not used.

| Project | Revision | Source references | Use |
| --- | --- | --- | --- |
| [openai/codex](https://github.com/openai/codex/tree/335c7f8ecab29c4462a553bbf174276d2c67a766) | `335c7f8ecab29c4462a553bbf174276d2c67a766`, rechecked unchanged at `b12ac84be9b5835259581c68dfc7cbe63d49e5f2` | `codex-rs/protocol/src/protocol.rs:2240-2273,3116-3199`, `codex-rs/history/src/rollout_payload.rs:33-72`, `codex-rs/rollout/src/recorder.rs:900-993,1747-1766,1892-1902`, `codex-rs/core/src/session/mod.rs:1656-1706,4703-4736` | `token_usage_record` envelope and fields, own-header-first write order, copied-fork prefixes, root `session_id`, line timestamps, and the 0.153.0-alpha.1 era in which each record precedes its `token_count`. |

Only records whose `thread_id` equals the file's own first-line `session_meta` id are stored. Copied prefixes, appended headers and foreign first lines fail closed, and legacy-era `token_count` lines only mark the day partial. The store's v1 schema gained the Codex extension in place: a data directory written by an earlier unshipped v1 shape is refused with `store_corrupt` by design and stays byte-unchanged. It is never migrated, backed up or deleted, so development uses a fresh data directory.

Codex acquisition is file-by-file best effort. Every observed change to device, inode, size or mtime restarts a bounded read from offset zero; unchanged unfinished scans resume their durable cursor, and unchanged EOF or pending tails read no content. The selected stamp must match the opened-before and opened-after stamps before committing a file batch. Earlier history and uncovered uncertainty survive rereads. Each read is limited to 1 MiB within the existing 8 MiB file and 64 MiB source per-pass ceilings. Repeated writes can restart large files and delay convergence; mutations concealed by identical metadata are outside this detection guarantee.

## Fixtures

All checked-in OpenCode test inputs are synthetic JSON or SQLite rows; they are not copied from a user database and contain no credentials.

| Fixture | Provenance and purpose |
| --- | --- |
| `Fixtures/harness/opencode/peer/cases.json` and `expected.json` | Hand-authored legacy, v2, and JSON records with independent expectations for explicit mismatches, derived totals, missing components, explicit zero, malformed counters, compaction, and delimiter-safe identities. |
| `Fixtures/harness/opencode/wal/schema.sql`, `rows.json`, `expected.json`, and `steps.json` | Hand-authored SQLite schema and rows for legacy/v2 decoding, WAL reads, parent-to-part replacement, revisions, mirrors, pruning, restart, and generation-tie history. `steps.json` supplies expected totals and pending state for each mutation. |
| `Fixtures/harness/opencode/daily/rows.json` and `expected.json` | Hand-authored legacy rows and their independent daily oracle: windows per zone (UTC, Europe/Riga 23 h and 25 h days, Asia/Kolkata), boundary records, a revision crossing local midnight, a pending group, an empty day, `validation_cases` (the window or the exact `invalid_request` field for each `{tz, now_ms}` refusal, including the America/Sao_Paulo 2015-10-18 midnight-gap day and the following day), the `midnight_gap` record at 2015-10-19 00:30 America/Sao_Paulo counted only in the following day, and a two-message JSON part-scan layout (`rows.json` `json_messages`, two step-finish parts each) with its `json_part_scan` oracle for cancellation. Consumed unchanged by `reported_today`, `contract_v1` and the Swift tests; nothing is generated from the implementation. |
| `Contracts/bridge-v1/*.json` | Response goldens equal to the provider's serialization of the fixtures above, and `requests-first-use.json`, the requests Swift encodes and the production codec parses. Hand-reviewed fixed files; tests compare and never rewrite them. |
| `Fixtures/hostile/opencode/cases.json` and `expected.json` | Hand-authored malformed records and hostile path cases with separate expected rejection outcomes. |
| `Fixtures/harness/codex/basic/` | Hand-authored record-era rollout (`sessions/2026/03/29/rollout-2026-03-29T09-00-00-basic.jsonl`) with full, absent-key and explicit-zero counters; `expected.json` holds the stored columns, file state, the daily snapshot and the Europe/Riga and Asia/Kolkata window oracle for records built at test time. |
| `Fixtures/harness/codex/incremental/` | Hand-authored parent (`base/`) and copied-fork child (`fork/`) rollouts, byte `steps.json` for partial-tail and append reads, and `expected.json` with the exact tail reads, per-step rows and fork ownership oracles. |
| `Fixtures/harness/codex/headers/` | Hand-authored appended-header, foreign-first-line, legacy, subagent, record-era, resumed-legacy and copied-prefix rollouts; `expected.json` holds per-file states, rows, day completeness, the legacy fork-child line spec and the `cli_version` era cases. |
| `Fixtures/hostile/codex/cases.json` and `expected.json` | Hand-authored hostile record lines (bad counters, timestamps, ids and JSON) with separate expected rejections. |

The upstream source snapshots and fact-check records used during planning are retained under `.devrites/work/quotern-core/references/`; they are research material, not runtime dependencies.
