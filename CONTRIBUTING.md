# Contributing

Thanks for considering a contribution. A few ground rules make the project
easier to maintain.

## Scope

`shannon` intentionally does **one** thing: observe L7 traffic with eBPF and
make it readable. PRs that broaden scope (full APM, metrics backends,
storage, dashboards, agents-of-agents) will usually be declined and suggested
as downstream projects that consume `shannon`'s JSON output.

## Development setup

Requires Linux ≥ 5.8 with BTF. See `shannon doctor` for exact requirements.

```bash
# one-time
rustup toolchain install nightly --component rust-src,rustfmt,clippy
rustup toolchain install stable  --component rustfmt,clippy
cargo install bpf-linker --locked

# build everything (BPF object + userspace binary)
cargo xtask build

# run (needs caps)
sudo ./target/debug/shannon

# tests
cargo xtask test
```

## What we review

- **Correctness.** Parsers must not panic on adversarial input. Fuzz targets
  live under `fuzz/`; run them before submitting changes to parser code.
- **No allocations in the hot path.** Event decode and flow reconstruction
  run per-packet; avoid `String`, `Vec::new`, heap-anything unless there is a
  comment justifying it.
- **BPF verifier friendliness.** Keep BPF programs small, bounded loops,
  explicit bounds checks before `bpf_probe_read_user`. Don't rely on
  optimizations — write code that passes the verifier without `-O3`.
- **No `unwrap()` / `expect()` in library code** except where a panic is
  genuinely the correct response (programmer error, invariant violation that
  makes continuing unsafe). Initialization paths in `main.rs` may use
  `expect()` with a clear actionable message.
- **Clippy clean.** `cargo xtask lint` must pass. We treat clippy pedantic as
  advisory; we treat clippy default and the subset we enable as hard required.
- **Security posture.** New data sources must document what they expose in
  `SECURITY.md` and participate in `--redact auto`.

## Commit hygiene

- Use conventional prefixes: `feat:`, `fix:`, `perf:`, `refactor:`, `docs:`,
  `test:`, `build:`, `ci:`, `chore:`.
- One logical change per commit. Rebase noise into nothing before requesting
  review.
- PRs should include a manual-test section describing what you ran and what
  you saw, especially for protocol parsers (paste a sample session).

## License

By submitting a contribution you agree that your work is licensed under both
Apache 2.0 and MIT at the project's option, matching the rest of the tree.
