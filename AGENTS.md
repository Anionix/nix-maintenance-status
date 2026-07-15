# Repository Instructions

## GitHub workflow

These rules apply to the owner's original repository:

- Start every work branch from the latest `origin/main`. Do not stack pull requests.
- Never work directly on `main`; use a dedicated branch for every change.
- Keep each pull request focused and around 250 changed lines. If more work is
  needed, merge the first pull request and start the next branch from the new
  `origin/main`.
- Use squash merge only.
- Before merging, resolve every review thread or confirm that it is outdated.
  If a merged review comment identifies a remaining defect, create an issue
  with the `bug` label.
- Code that implements a state transition must include a concise LLM contract
  comment describing its valid states, triggers, and invariants.
- Keep `flake.nix` and `flake.lock` present and reproducible.
- Optimize repository structure and documentation for low cognitive load and
  agent navigability.
- If the appropriate engineering flow is unclear, use the `ask-matt` skill.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues. See
`docs/agents/issue-tracker.md`.

### Triage labels

Incoming requests use the five canonical triage roles. See
`docs/agents/triage-labels.md`.

### Domain docs

This repository uses a single-context domain documentation layout. See
`docs/agents/domain.md`.
