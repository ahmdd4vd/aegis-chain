use semver::Version;

/// Source of software-provenance verification results (e.g. Sigstore / cosign).
///
/// Implementors answer, for a given package, whether its build provenance
/// (SLSA attestation, cosign signature, ...) has been cryptographically
/// verified. The decision engine uses a `true` answer to mark the package as
/// having `EvidenceKind::Provenance`, which lowers the evidence gap and thus
/// the overall risk score.
///
/// This trait is intentionally side-effect free and object safe so it can be
/// mocked in tests and supplied behind an opt-in CLI flag (network/verification
/// is never performed unless the caller wires a concrete source).
pub trait ProvenanceSource {
    fn has_provenance(&self, name: &str, version: &Version) -> bool;
}
