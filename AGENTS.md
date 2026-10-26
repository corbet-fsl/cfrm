# cfrm agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cfrm` — native suite green except
  `native_record` (3 tests need `CBLC_RECORD_EPOCH_FIXTURE`, CI-provided; without
  it they fail at `tests/native_record/fixture.rs:38`)
- `~/agents/scratch/cbuild <lane> fmt -p cfrm -- --check` — must be clean
- `clippy -p cfrm --all-targets -- -D warnings` currently fails on pre-existing
  `tests/native_record/g1.rs:50` (single-element loop); fix the code, never the lint
- Full gate (wasm vectors, nightly 100% reachable line+branch coverage, TS parity)
  runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Ephemeral only: one shared `Volatile` handle, one scope per community; no
  permanent member state
  -> `tests/runtime.rs::missing_accounting_currentness_refuses_every_member_action_without_attendance`
- No request/access/body logging; value-free diagnostics only (structural; `src/http.rs`)
- Every response, success and refusal, is `Cache-Control: no-store`
  -> `src/http_tests.rs::result`, `tests/runtime.rs::call`
- Exact single Host + Origin; forwarded headers never grant authority
  -> `src/http_tests.rs::exact_origin_host_media_and_duplicate_header_checks_precede_body_work`
- One action registry (21 actions) generates HTTP/OpenAPI/TS/MCP
  -> `src/http_tests.rs::all_actions_are_registry_derived_and_no_authority_can_be_fabricated`
- Strict wire decoder (`version=1`, `deny_unknown_fields`, dup/unknown/oversize refuse)
  -> `src/portable_tests.rs::wire_decoder_refuses_duplicate_unknown_and_unbounded_input`
- Missing G2 frontier/ZK currentness refuses every governed action, creates no attendance
  -> `tests/runtime.rs::missing_accounting_currentness_refuses_every_member_action_without_attendance`
- `room_*` carry only opaque `room_pass` + `command`, never presence credentials
  -> `src/portable_tests.rs::room_api_refuses_authenticated_presence_bindings`
- Forum follows the genesis-signed community name, not the registry id
  -> `tests/created_community.rs::a_forum_follows_a_created_community_under_its_signing_name`

Pointers: `src/api.rs` (registry), `src/runtime.rs`, `src/http.rs`,
`docs/CONTRACT.md`, `docs/COVERAGE.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
First-party deps follow `main` with one locked revision; no registry publication.
