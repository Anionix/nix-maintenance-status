use std::fmt;

use crate::diagnostic::{DiagnosticInput, EvidenceClass};
use crate::evidence::ProviderEvidence;

#[derive(Clone)]
pub struct EvidenceId(usize);

impl fmt::Debug for EvidenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceId(<opaque>)")
    }
}

#[derive(Debug, Clone)]
pub struct ReportEvidence {
    id: EvidenceId,
    value: ProviderEvidence,
}

impl ReportEvidence {
    pub fn id(&self) -> EvidenceId {
        self.id.clone()
    }
    pub const fn value(&self) -> ProviderEvidence {
        self.value
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceLedger {
    entries: Vec<ReportEvidence>,
}

impl EvidenceLedger {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &ReportEvidence> + '_ {
        self.entries.iter()
    }
    pub(crate) fn owns(&self, evidence: &ReportEvidence) -> bool {
        self.entries
            .iter()
            .any(|entry| std::ptr::eq(entry, evidence))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    LegacyInput,
}

// LLM contract: `build_ledger` only triggers Provider → Subject → component canonicalization with opaque IDs; #44 owns scheduler identity/capture, so rows are not candidates.
// Claims Known/Unknown reject empty/duplicate/reversed/foreign refs; Unknown != Absent; legacy rejected; pure/read-only/offline, no telemetry, and no GC execution.
pub fn build_ledger(input: &DiagnosticInput) -> Result<EvidenceLedger, LedgerError> {
    let evidence = input.evidence().ok_or(LedgerError::LegacyInput)?;
    let mut values = evidence.entries().to_vec();
    values.sort_by_key(|value| {
        (
            value.provider().catalog_order(),
            value.subject(),
            value.component(),
        )
    });
    let entries = values
        .into_iter()
        .enumerate()
        .map(|(ordinal, value)| ReportEvidence {
            id: EvidenceId(ordinal),
            value,
        })
        .collect();
    Ok(EvidenceLedger { entries })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportUnknown {
    MissingEvidence,
    DependentClaimUnknown,
}

#[derive(Debug, Clone)]
pub struct ReportProvenance {
    class: EvidenceClass,
    evidence: Vec<EvidenceId>,
}

impl ReportProvenance {
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.class
    }
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence
    }

    fn from_evidence(
        class: EvidenceClass,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        if evidence.is_empty() || evidence.iter().any(|entry| !ledger.owns(entry)) {
            return None;
        }
        let ids: Vec<_> = evidence.iter().map(|entry| entry.id.clone()).collect();
        if ids.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return None;
        }
        Some(Self {
            class,
            evidence: ids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportConclusion<T> {
    Known(T),
    Unknown(ReportUnknown),
}

#[derive(Debug, Clone)]
pub struct ReportClaim<T> {
    conclusion: ReportConclusion<T>,
    provenance: ReportProvenance,
}

impl<T> ReportClaim<T> {
    pub const fn conclusion(&self) -> &ReportConclusion<T> {
        &self.conclusion
    }
    pub const fn provenance(&self) -> &ReportProvenance {
        &self.provenance
    }
    // Constructors consume ledger-owned evidence tokens, never caller IDs.
    #[allow(dead_code)] // consumed by the classifier slice
    pub(crate) fn known(
        value: T,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        Self::known_with_class(value, EvidenceClass::Observed, ledger, evidence)
    }
    #[allow(dead_code)] // consumed by the classifier slice
    pub(crate) fn known_with_class(
        value: T,
        class: EvidenceClass,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        Some(Self {
            conclusion: ReportConclusion::Known(value),
            provenance: ReportProvenance::from_evidence(class, ledger, evidence)?,
        })
    }
    #[allow(dead_code)] // consumed by the classifier slice
    pub(crate) fn unknown(
        reason: ReportUnknown,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        Some(Self {
            conclusion: ReportConclusion::Unknown(reason),
            provenance: ReportProvenance::from_evidence(EvidenceClass::Unknown, ledger, evidence)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ObservationComponent, Presence, Provider, Subject, UnavailableReason};

    #[test]
    fn claims_keep_value_and_evidence_provenance() {
        let unavailable = ReportEvidence {
            id: EvidenceId(5),
            value: ProviderEvidence::new(
                Provider::NixDarwinLaunchd,
                Subject::System,
                ObservationComponent::Configuration,
                Presence::Unavailable(UnavailableReason::InterfaceUnavailable),
            )
            .unwrap(),
        };
        let ledger = EvidenceLedger {
            entries: vec![
                ReportEvidence {
                    id: EvidenceId(4),
                    value: ProviderEvidence::new(
                        Provider::NixDarwinLaunchd,
                        Subject::System,
                        ObservationComponent::Runtime,
                        Presence::Present,
                    )
                    .unwrap(),
                },
                unavailable,
            ],
        };
        let entries: Vec<_> = ledger.iter().collect();
        let evidence = entries[0];
        assert_eq!(format!("{:?}", evidence.id()), "EvidenceId(<opaque>)");
        assert!(!format!("{:?}", ledger).contains("EvidenceId(4)"));
        let known = ReportClaim::known("loaded", &ledger, &[evidence]).unwrap();
        assert_eq!(known.provenance().evidence_ids().len(), 1);
        assert!(matches!(
            known.conclusion(),
            ReportConclusion::Known("loaded")
        ));
        let inferred =
            ReportClaim::known_with_class("mapped", EvidenceClass::Inferred, &ledger, &[evidence])
                .unwrap();
        assert_eq!(
            inferred.provenance().evidence_class(),
            EvidenceClass::Inferred
        );
        let unknown: ReportClaim<()> =
            ReportClaim::unknown(ReportUnknown::MissingEvidence, &ledger, &[entries[1]]).unwrap();
        assert!(matches!(
            unknown.conclusion(),
            ReportConclusion::Unknown(ReportUnknown::MissingEvidence)
        ));
        let copied = (*evidence).clone();
        assert!(ReportClaim::known("copied", &ledger, &[&copied]).is_none());
        assert!(ReportClaim::known("empty", &ledger, &[]).is_none());
        assert!(ReportClaim::known("reversed", &ledger, &[entries[1], entries[0]]).is_none());
    }
}
