# Issue tracker: GitHub

Issues and PRDs for this repository live as GitHub Issues. Use the `gh` CLI for
all operations and infer the repository from `git remote -v`.

## Conventions

- Create an issue with `gh issue create --title "..." --body "..."`.
- Read the full issue and comments with `gh issue view <number> --comments`.
- List issues with `gh issue list`, including labels and comments in JSON when
  a skill needs structured input.
- Apply or remove labels with `gh issue edit`.
- Comment with `gh issue comment` and close with `gh issue close`.

GitHub shares one number space across issues and pull requests. Resolve an
ambiguous number with `gh pr view <number>` and then fall back to
`gh issue view <number>`.

## Pull requests as a triage surface

**PRs as a request surface: no.**

External pull requests are not treated as incoming feature requests by the
`triage` skill. Change this flag to `yes` only if that policy changes.

## Skill operations

- When a skill says "publish to the issue tracker", create a GitHub Issue.
- When a skill says "fetch the relevant ticket", read the full GitHub Issue and
  its comments.
- Publish specifications as parent Issues and implementation tickets as
  sub-issues.
- Represent blockers with GitHub native issue dependencies. If the endpoint is
  unavailable, use a `Blocked by: #<number>` line in the ticket body.
- Apply `ready-for-agent` only after a ticket is fully specified.

## Wayfinding operations

Use one Issue labelled `wayfinder:map` as the map and link decision tickets as
sub-issues. Use `wayfinder:<type>` labels for `research`, `prototype`,
`grilling`, and `task` tickets when the wayfinder flow is active. A ticket is
on the frontier only when every blocker is closed and it has no assignee.
