# Nix Maintenance Diagnostics

This context describes how the project communicates claims about automated Nix
maintenance without overstating what the local machine proves.

## Language

**Observation**:
A fact read directly from the local system without attributing why it exists.
_Avoid_: Proof, configuration

**Authority**:
Upstream documentation or source that defines how a configuration choice
produces an observable system artifact. Its version is recorded when known and
explicitly marked unknown when it cannot be established locally.
_Avoid_: Hint, assumption

**Inference**:
A conclusion derived from one or more Observations through an Authority. An
Inference is never presented as a directly evaluated configuration value.
_Avoid_: Observation, fact

**Unknown**:
The result when available Observations and Authorities cannot support a unique
conclusion.
_Avoid_: Disabled, absent

**Provenance**:
The trace connecting a reported claim to its Observations and Authorities,
including whether the claim is an Observation, Inference, or Unknown.
_Avoid_: Source, origin

**Claim**:
A value-level conclusion paired with the Provenance that supports it. A report
contains multiple Claims rather than collapsing them into one overall status.
_Avoid_: Field, flag

**Configuration**:
The Claim about whether a persistent automatic-GC artifact is detected. On
macOS, it is based only on the nix-darwin launchd plist and does not assert the
evaluated value of `nix.gc.automatic`.
_Avoid_: Enabled, disabled

**Runtime**:
The Claim about whether the automatic-GC launchd job is currently loaded. It is
independent from Configuration and says nothing about persistent intent.
_Avoid_: Configuration, health

**Consistency**:
The Inference describing whether the independently observed Configuration and
Runtime Claims agree. Consistency does not mean that GC is correctly configured
or healthy.
_Avoid_: Correctness, overall status
