## Summary

Describe the problem and the focused change that addresses it.

## Evidence

State which reported values are observed, inferred, or unavailable.

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --all-targets`
- [ ] `nix flake check`
- [ ] User-facing documentation is updated in both `README.md` and `README.ja.md`.
- [ ] The change remains read-only and telemetry-free.
