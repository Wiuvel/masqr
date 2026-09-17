//! The TLS session the tunnel runs inside — over TCP for HTTP/2, inside QUIC for HTTP/3.
//!
//! Two things are unusual, both from how WARP proves who is calling:
//!
//! * **The client presents a certificate**, self-signed with the P-256 key registration enrolled.
//!   That enrollment is the whole authentication — the endpoint recognises the key, not a name or a
//!   chain. It is also why this handshake can never look exactly like a browser's.
//! * **The server is not checked against a certificate authority.** Registration told us the public
//!   key the endpoint should present, and comparing that key is a stronger statement than a chain
//!   to a public root — and the only check available for a certificate no authority signed.

use std::sync::Arc;

use p256::pkcs8::{DecodePublicKey as _, EncodePublicKey as _};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use x509_cert::der::{Decode as _, Encode as _};

use crate::warp::Identity;

#[derive(Debug, thiserror::Error)]
/// Why the session that carries the tunnel could not be built from this identity.
pub enum TlsSetupError {
    #[error("the identity's private key is not a usable P-256 key: {0}")]
    PrivateKey(String),
    #[error("the identity's endpoint public key is not readable: {0}")]
    EndpointKey(String),
    #[error("building the client certificate: {0}")]
    Certificate(String),
    #[error("rustls: {0}")]
    Rustls(#[from] TlsError),
}

/// Build the client configuration for one MASQUE connection, offering exactly one protocol.
///
/// One, because each carrier speaks one: `h2` over TCP, `h3` over QUIC. An endpoint that will not
/// agree to it is not one the carrier can use, and failing in the handshake is better than
/// discovering it later. The identity and the pin are the same over both.
pub fn client_config(
    identity: &Identity,
    alpn: &[u8],
) -> Result<Arc<rustls::ClientConfig>, TlsSetupError> {
    let (cert_der, key_der) = client_certificate(identity)?;
    let expected = expected_endpoint_spki(identity)?;

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedKeyVerifier { expected }))
        .with_client_auth_cert(vec![cert_der], key_der)?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(config))
}

/// A short-lived self-signed certificate carrying the enrolled key.
///
/// Nothing reads its subject, its validity or its extensions — the endpoint looks at the public
/// key. It is generated per connection rather than stored, because there is nothing in it worth
/// keeping: the key it certifies is already in the identity.
fn client_certificate(
    identity: &Identity,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TlsSetupError> {
    use base64::Engine as _;

    let sec1 = base64::engine::general_purpose::STANDARD
        .decode(&identity.private_key_sec1)
        .map_err(|e| TlsSetupError::PrivateKey(e.to_string()))?;
    let secret = p256::SecretKey::from_sec1_der(&sec1)
        .map_err(|e| TlsSetupError::PrivateKey(e.to_string()))?;

    // rcgen wants PKCS#8; the identity keeps SEC1 so that a file written by either core is
    // readable by the other. Converting here costs one re-encode per connection.
    let pkcs8 = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&secret)
        .map_err(|e| TlsSetupError::PrivateKey(e.to_string()))?;
    let key_pair = rcgen::KeyPair::try_from(pkcs8.as_bytes())
        .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
    let params = rcgen::CertificateParams::default();
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;

    Ok((
        cert.der().clone(),
        PrivateKeyDer::try_from(pkcs8.as_bytes().to_vec())
            .map_err(|e| TlsSetupError::PrivateKey(e.to_string()))?,
    ))
}

/// The endpoint's public key as SPKI DER, decoded from the PEM registration handed back.
fn expected_endpoint_spki(identity: &Identity) -> Result<Vec<u8>, TlsSetupError> {
    let key = p256::PublicKey::from_public_key_pem(&identity.endpoint_public_key_pem)
        .map_err(|e| TlsSetupError::EndpointKey(e.to_string()))?;
    Ok(key
        .to_public_key_der()
        .map_err(|e| TlsSetupError::EndpointKey(e.to_string()))?
        .as_bytes()
        .to_vec())
}

/// Accepts exactly one server: the one whose certificate carries the key registration enrolled.
#[derive(Debug)]
struct PinnedKeyVerifier {
    expected: Vec<u8>,
}

impl ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let cert = x509_cert::Certificate::from_der(end_entity)
            .map_err(|e| TlsError::General(format!("endpoint certificate: {e}")))?;
        let presented = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| TlsError::General(format!("endpoint public key: {e}")))?;
        if presented != self.expected {
            // Deliberately not "certificate invalid": nothing is wrong with the certificate, it
            // simply belongs to a different endpoint than the one this identity was enrolled with.
            return Err(TlsError::General(
                "the endpoint presented a different public key than registration enrolled".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
