# Contributing

Thanks for helping improve `nix-maintenance-status`. This is an experimental
personal project, so maintenance and review are provided on a best-effort basis.

## Before opening an issue

- Confirm that the problem is about macOS with nix-darwin.
- Search existing issues for the same behavior.
- Remove private paths, usernames, or other sensitive data from diagnostic output.
- Use GitHub's private vulnerability reporting instead of a public issue for
  suspected security problems.

## Development setup

Use the pinned Nix development environment:

```console
nix develop
```

Before submitting a pull request, run:

```console
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
nix flake check
```

## Pull requests

- Keep each pull request focused on one problem.
- Add or update tests for behavior changes.
- Preserve the read-only and no-telemetry guarantees.
- Update both `README.md` and `README.ja.md` when user-facing documentation changes.
- Describe which evidence is observed, inferred, or unavailable.
- Do not weaken or skip a failing quality gate.

By contributing, you agree that your contribution is licensed under the MIT
License used by this repository.
