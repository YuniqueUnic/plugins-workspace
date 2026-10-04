# File-backed authenticated updater

Branch: `syzygy/file-backed-updater-v2.13.1`.
Upstream baseline: `updater-v2.13.1`, commit
`e51128438011755f9e7277bad29b8c0978cf281c` from
<https://github.com/tauri-apps/plugins-workspace/releases/tag/updater-v2.13.1>.
Crates.io identifies 2.13.1 as the latest stable release on 2026-10-04:
<https://crates.io/api/v1/crates/tauri-plugin-updater>.

This fork keeps `Update::verify_reader` and its owning `VerifiedUpdate`: stream
an existing/resumed download into a private file while authenticating it, then
install that exact snapshot or atomically save it without replacing an existing
file. Native installers consume a `Read + Seek` source instead of requiring a
second whole-package allocation. Upstream does not expose this capability; the
consumer cannot supply its downloader's file through the upstream byte-only API
without losing that memory and ownership boundary.

The 2.13.1 upgrade is B-type maintenance. The simplification review rejects a
second signed-version policy or an updater wrapper; the structural review
rejects a manifest-only version change and any streaming bypass of the upstream
security policy. Merge the actual release, preserve the file-backed owner, and
reuse upstream `verify_signed_version` after streaming signature finalization.
No compatibility branch, public fallback API or additional runtime dependency is
introduced. The original six snapshot/signature regressions remain; three more
exercise signed-version matches/mismatches, required version metadata, and a
forged trusted comment. Trusted metadata is used only after its global signature
has been verified.

The fork retains upstream's byte API. Both byte and file verification enforce
`requireSignedVersion` and reject any present signed version that differs from
the announced release. Defaults remain upstream-owned. Platform installers and
the existing ownership API are unchanged beyond the upstream merge.

2026-10-04 validation:

- `mbx test -p tauri-plugin-updater --lib --locked`: 14 passed on macOS aarch64
  (nine file-backed regressions and five upstream signed-version tests).
- `mbx check -p tauri-plugin-updater --locked --all-targets --all-features` and
  `mbx clippy -p tauri-plugin-updater --locked --all-targets --all-features -- -D warnings`:
  passed on macOS aarch64.
- `mbx check -p tauri-plugin-updater --locked --lib --no-default-features --features native-tls --target x86_64-pc-windows-gnu`:
  passed; the same command with `native-tls,zip` also passed. These are compilation
  checks, not Windows installer execution.
- Linux `--target x86_64-unknown-linux-gnu --no-default-features --features rustls-tls`
  could not compile GTK/GObject dependencies because this macOS host has no Linux
  pkg-config/sysroot configuration. Linux installer execution remains unverified.
- `rustfmt --edition 2024 --check` passed for modified updater source and tests;
  source scanning found no path attributes or source inclusion macros.
- All Cargo commands used `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
  CARGO_INCREMENTAL=0 MBX_GC_AUTO=false`. The upstream release lockfile remained
  unchanged. Parent-workspace consumer checks are recorded separately.
