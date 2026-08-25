use semver::Version;

/// Source of external vulnerability/advisory findings for a package version.
///
/// Implementations stay out of `aegis-core` so the domain crate remains
/// deterministic and network-free; the real OSV-backed implementation lives in
/// `aegis-advisory` and is injected by the CLI only when the user opts in.
pub trait AdvisorySource {
    /// Normalized severity in `[0, 1]` for `name@version`, or `None` when no
    /// finding is known. Higher means more review-worthy.
    fn severity_for(&self, name: &str, version: &Version) -> Option<f64>;
}
