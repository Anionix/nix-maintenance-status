# Domain Docs

This repository uses a single domain context.

## Before exploring

Read these sources when they exist:

- `CONTEXT.md` at the repository root for canonical domain language.
- `docs/adr/` for decisions that affect the area being changed.

Their absence is not an error. The `domain-modeling` skill creates them lazily
when the first term or qualifying architectural decision is resolved.

## File structure

```text
/
├── CONTEXT.md
├── docs/
│   └── adr/
└── src/
```

`CONTEXT.md` is a glossary, not a specification or implementation notebook.
Definitions describe what a domain term is and identify synonyms to avoid.

## Consumer rules

- Use the glossary's canonical vocabulary in Issues, tests, and design work.
- If a needed term is absent, reconsider whether it is project-specific before
  adding it.
- Surface conflicts with an existing ADR instead of silently overriding it.
- Create an ADR only for a hard-to-reverse, surprising decision that resolves a
  real trade-off.
