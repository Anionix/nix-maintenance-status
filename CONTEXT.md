# Nix Maintenance Diagnostics

This context is the glossary for the experimental 0.2 read-only inventory of
Nix garbage-collection automations on macOS+nix-darwin and Linux. The normative
contract is [Spec #27](https://github.com/Anionix/nix-maintenance-status/issues/27);
this file keeps the words used by that contract unambiguous.

## Evidence and claims

**Observation**:
A normalized fact obtained from a catalogued local observation seam. It says
what was observed, not why the artifact exists. _Avoid_: proof, configuration.

**Evidence**:
A typed, validated, normalized input record owned by the report. Evidence may
be absent or unavailable, but it never retains raw bytes, paths, command text,
stdout, stderr, account metadata, control characters, or OS error strings.
_Avoid_: capture, raw output.

**Authority**:
An exact upstream source or scheduler contract that defines command semantics,
an official automation mapping, or provider behavior. Authority is resolved
only from the embedded source-controlled catalog; runtime network, plugins,
caller-supplied officiality, ranges, and nearest-version matching are excluded.
_Avoid_: hint, assumption.

**AuthorityRole**:
One of `GcOperationSemantics`, `AutomationMapping`, or `SchedulerSemantics`.
Each role is independent and resolves to `Resolved`, `Unresolved`, `NotClaimed`,
or `NotApplicable`. `NotClaimed` means this artifact was not attributed; it
does not prove that no official mapping exists.

**Inference**:
A conclusion derived from normalized Observations through a resolved
Authority and an embedded inference rule. An Inference is never a direct
evaluation of a Nix configuration option. _Avoid_: observation, fact.

**Unknown**:
The result when available Evidence or Authority cannot support a unique
conclusion. Unknown is not absent, disabled, or not configured, and propagates
only to directly dependent Claims and relations. _Avoid_: false, disabled.

**Provenance**:
The typed trace for a Claim: opaque report-local EvidenceId references,
EvidenceClass, applicable AuthorityRole results, and an optional catalog rule.
EvidenceIds are private report references, not persistence keys, user-facing
identities, or rendered output. _Avoid_: raw source dump.

**Claim**:
A value-level conclusion paired with Provenance. A report has multiple Claims
and never collapses them into one overall health value. `Conclusion<T>` is
`Known(T)` or `Unknown(reason)`; optional domain values use
`Applicable(T)` or `NotApplicable`, not an untyped `Option<T>` state.

## Inventory vocabulary

**GcAutomation**:
One independent inventory candidate with a report-local opaque AutomationId,
privacy-safe Subject, catalog Provider, fixed Claims, and shared normalized
Evidence. Candidate retention does not assert that Nix GC will run.

**Provider**:
A catalog-bounded scheduler family/instance such as launchd, systemd, Cronie,
anacron, or fcron. Provider identity is separate from Subject identity and
AuthorityRole; a scheduler name alone never establishes an official Nix mapping.

**Subject**:
The privacy-safe scope identity `system`, `uid:<n>`, or a deterministic
`subject:unresolved:<ordinal>`. Usernames and account labels are ephemeral
adapter observations, never report identity or rendered output.

**ScanScope**:
The finite request `System`, `CurrentUser`, `Default` (system plus current
user), or `AllUsers` (system plus current user plus valid numeric UIDs from a
bounded local `/etc/passwd` snapshot). No NSS/network enumeration, arbitrary
UID range, user switching, or automatic privilege escalation is performed.

**Coverage**:
Observation completeness, not health or correctness. The canonical leaf matrix
is `Provider × Subject × ObservationComponent` with `Covered`,
`Unavailable(reason)`, or `NotApplicable`; aggregates are `Complete`, `Partial`,
or `Unavailable`. A known-empty inventory can be Complete. `Absent`,
`PresentEmpty`, and `Unavailable` are distinct provider observations.

**ObservationComponent**:
One of `Discovery`, `Configuration`, `Runtime`, `Schedule`, `Command`,
`Activity`, `Runs`, or `LastResult`. A probe failure lowers only its applicable
leaf; a fully read unsupported wrapper remains Covered with an Unknown Claim.

**Schedule**:
A provider-native normalized timing value. Launchd, systemd, Cronie, anacron,
and fcron semantics remain distinct; a common display projection is not
Evidence, Authority, identity, or proof of equivalence.

**Configuration**:
The Claim about persistent scheduler definition Evidence. For official Nix GC,
it can be inferred only when the complete pinned NixOS or nix-darwin mapping
fingerprint matches; a detected scheduler artifact is not direct proof of
`nix.gc.automatic`.

**Runtime**:
The independent Claim about the provider's current manager/job observation.
Runtime does not establish persistent intent, successful past execution, or
configuration correctness.

**Consistency**:
A dependent Inference comparing independent Configuration and Runtime Claims.
It does not mean that GC is configured correctly, healthy, or guaranteed to run.

**Relation**:
A pure, deterministic finding between inventory candidates (or a local node
finding) such as Definition/Behavior/Semantic equivalence, overlap, conflict,
or Indeterminate. Relations have their own Coverage and never become an
overall health score or mutate Claims.

**Provider Catalog**:
The embedded, append-only set of stable family IDs and exact SourcePin or
ContractPin identities, citations, mapping fingerprints, package/patch
IntegrityPins, and lifecycle metadata. `catalog-check` is offline and
deterministic; diagnostics never audit or update the catalog.
