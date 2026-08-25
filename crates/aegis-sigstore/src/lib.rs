//! Sigstore / cosign provenance verification for Aegis Chain.
//!
//! `CosignProvenanceProvider` implements [`aegis_core::ProvenanceSource`] by
//! verifying a Sigstore *bundle* (the `verify-bundle` JSON format) for a given
//! crate `name@version`. Verification checks:
//!
//! 1. The DSSE envelope signature against the verification material's public
//!    key (extracted from a Fulcio X.509 certificate when present, otherwise a
//!    raw `publicKey` as used by `cosign verify --key`).
//! 2. The envelope payload is an in-toto statement whose `predicateType`
//!    identifies a SLSA provenance attestation.
//!
//! This is intentionally self-contained (pure Rust, no network) so it can run
//! offline in CI; the caller decides *where* bundles come from.

use aegis_core::ProvenanceSource;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use semver::Version;
use serde::Deserialize;
use std::path::PathBuf;
use x509_cert::der::Decode;
use x509_cert::Certificate;

#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid bundle json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("no usable verification material (certificate or public key)")]
    MissingMaterial,
    #[error("missing dsse signature")]
    MissingSignature,
    #[error("not a SLSA provenance attestation")]
    NotSlsaProvenance,
    #[error("signature verification failed")]
    Signature,
    #[error("invalid public key")]
    PublicKey,
}

#[derive(Debug, Deserialize)]
struct Bundle {
    #[serde(default, rename = "verificationMaterial")]
    verification_material: VerificationMaterial,
    #[serde(rename = "dsseEnvelope")]
    dsse_envelope: DsseEnvelope,
}

#[derive(Debug, Default, Deserialize)]
struct VerificationMaterial {
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default, rename = "publicKey")]
    public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DsseEnvelope {
    #[serde(default)]
    payload: String,
    #[serde(rename = "payloadType", default)]
    payload_type: Option<String>,
    signatures: Vec<DsseSignature>,
}

#[derive(Debug, Deserialize)]
struct DsseSignature {
    sig: String,
}

#[derive(Debug, Deserialize)]
struct IntotoStatement {
    #[serde(rename = "predicateType")]
    predicate_type: String,
}

/// Provenance provider backed by a directory of Sigstore bundle files.
///
/// Each bundle is named `{name}@{version}.json` (for example
/// `serde@1.0.210.json`) and contains a verified cosign/Sigstore bundle.
pub struct CosignProvenanceProvider {
    bundles_dir: PathBuf,
}

impl CosignProvenanceProvider {
    pub fn new(bundles_dir: PathBuf) -> Self {
        Self { bundles_dir }
    }

    pub fn verify_bundle(&self, name: &str, version: &str) -> Result<bool, ProvenanceError> {
        let path = self.bundles_dir.join(format!("{name}@{version}.json"));
        let content = std::fs::read_to_string(&path)?;
        verify_cosign_bundle(&content)
    }
}

impl ProvenanceSource for CosignProvenanceProvider {
    fn has_provenance(&self, name: &str, version: &Version) -> bool {
        self.verify_bundle(name, &version.to_string())
            .unwrap_or(false)
    }
}

/// Verify a Sigstore bundle's JSON content, returning `true` only when the
/// DSSE signature is valid and the payload is a SLSA provenance attestation.
pub fn verify_cosign_bundle(content: &str) -> Result<bool, ProvenanceError> {
    let bundle: Bundle = serde_json::from_str(content)?;

    let payload = STANDARD.decode(&bundle.dsse_envelope.payload)?;
    let payload_type = bundle
        .dsse_envelope
        .payload_type
        .as_deref()
        .unwrap_or_default();
    if !payload_type.contains("in-toto") {
        return Err(ProvenanceError::NotSlsaProvenance);
    }

    let statement: IntotoStatement = serde_json::from_slice(&payload)?;
    if !statement.predicate_type.contains("slsa.dev/provenance") {
        return Err(ProvenanceError::NotSlsaProvenance);
    }

    let signature = bundle
        .dsse_envelope
        .signatures
        .first()
        .ok_or(ProvenanceError::MissingSignature)?;
    let sig = Signature::from_slice(&STANDARD.decode(&signature.sig)?)
        .map_err(|_| ProvenanceError::Signature)?;

    let material = &bundle.verification_material;
    let verifying_key = if let Some(cert_b64) = &material.certificate {
        let cert_der = STANDARD.decode(cert_b64)?;
        let cert = Certificate::from_der(&cert_der).map_err(|_| ProvenanceError::PublicKey)?;
        let raw = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let key = p256::PublicKey::from_sec1_bytes(raw).map_err(|_| ProvenanceError::PublicKey)?;
        VerifyingKey::from(key)
    } else if let Some(key_b64) = &material.public_key {
        let raw = STANDARD.decode(key_b64)?;
        let key = p256::PublicKey::from_sec1_bytes(&raw).map_err(|_| ProvenanceError::PublicKey)?;
        VerifyingKey::from(key)
    } else {
        return Err(ProvenanceError::MissingMaterial);
    };

    verifying_key
        .verify(&payload, &sig)
        .map_err(|_| ProvenanceError::Signature)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::Signer;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};

    fn slsa_payload() -> Vec<u8> {
        br#"{"predicateType":"https://slsa.dev/provenance/v1","subject":[],"predicate":{}}"#
            .to_vec()
    }

    fn non_slsa_payload() -> Vec<u8> {
        br#"{"predicateType":"https://example.com/not-slsa","subject":[]}"#.to_vec()
    }

    fn bundle_with(signing: &SigningKey, payload: &[u8]) -> String {
        let sig: P256Signature = signing.sign(payload);
        let verifying = VerifyingKey::from(signing);
        let pub_b64 = STANDARD.encode(verifying.to_encoded_point(false).as_bytes());
        let payload_b64 = STANDARD.encode(payload);
        let sig_b64 = STANDARD.encode(sig.to_bytes());
        format!(
            r#"{{"verificationMaterial":{{"publicKey":"{}"}},"dsseEnvelope":{{"payload":"{}","payloadType":"application/vnd.in-toto+json","signatures":[{{"sig":"{}"}}]}}}}"#,
            pub_b64, payload_b64, sig_b64
        )
    }

    #[test]
    fn verifies_valid_slsa_bundle() {
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let bundle = bundle_with(&signing, &slsa_payload());
        assert!(verify_cosign_bundle(&bundle).unwrap());
    }

    #[test]
    fn rejects_wrong_key() {
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let other = SigningKey::random(&mut rand::rngs::OsRng);
        let payload = slsa_payload();
        let sig: P256Signature = signing.sign(&payload);
        let other_vk = VerifyingKey::from(&other);
        let other_pub = STANDARD.encode(other_vk.to_encoded_point(false).as_bytes());
        let bundle = format!(
            r#"{{"verificationMaterial":{{"publicKey":"{}"}},"dsseEnvelope":{{"payload":"{}","payloadType":"application/vnd.in-toto+json","signatures":[{{"sig":"{}"}}]}}}}"#,
            other_pub,
            STANDARD.encode(&payload),
            STANDARD.encode(sig.to_bytes())
        );
        assert!(!verify_cosign_bundle(&bundle).unwrap_or(false));
    }

    #[test]
    fn rejects_non_slsa_predicate() {
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let bundle = bundle_with(&signing, &non_slsa_payload());
        assert!(matches!(
            verify_cosign_bundle(&bundle),
            Err(ProvenanceError::NotSlsaProvenance)
        ));
    }

    #[test]
    fn provider_resolves_bundle_file() {
        let dir = tempfile::tempdir().unwrap();
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let bundle = bundle_with(&signing, &slsa_payload());
        std::fs::write(dir.path().join("demo@1.0.0.json"), bundle).unwrap();

        let provider = CosignProvenanceProvider::new(dir.path().to_path_buf());
        assert!(provider.has_provenance("demo", &Version::new(1, 0, 0)));
        assert!(!provider.has_provenance("missing", &Version::new(1, 0, 0)));
    }
}
