//! The two key pairs registration needs, and the encodings the API expects them in.
//!
//! They are different curves for different reasons. The **curve25519** pair exists only to satisfy
//! `POST /reg`, which registers a WireGuard device and accepts nothing else; its public half is
//! sent once and neither half is ever used again. The **P-256** pair is the one that matters: its
//! public half is enrolled as the MASQUE key, and its private half signs the client certificate
//! the tunnel's TLS handshake presents.

use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::EncodePublicKey as _;

#[derive(Debug, thiserror::Error)]
/// Why a key pair could not be generated or read back.
pub enum KeyError {
    #[error("encoding the P-256 key: {0}")]
    Encode(String),
}

/// The MASQUE key pair, in the encodings the rest of the flow needs.
pub struct MasqueKeyPair {
    /// SEC1 DER, base64 — how the identity file carries the private half.
    pub private_sec1_base64: String,
    /// SPKI DER, base64 — what `PATCH /reg/{id}` enrolls.
    pub public_spki_base64: String,
}

impl MasqueKeyPair {
    /// A fresh key pair for a device that is about to be registered.
    pub fn generate() -> Result<Self, KeyError> {
        let secret = p256::SecretKey::random(&mut rand::thread_rng());

        // SEC1 for the private half: the same encoding Go's `MarshalECPrivateKey` produces, so an
        // identity written by either implementation is readable by the other. That matters while
        // both cores exist side by side.
        let private = secret
            .to_sec1_der()
            .map_err(|e| KeyError::Encode(e.to_string()))?;
        let public = secret
            .public_key()
            .to_public_key_der()
            .map_err(|e| KeyError::Encode(e.to_string()))?;

        Ok(Self {
            private_sec1_base64: super::api::b64(private.as_ref()),
            public_spki_base64: super::api::b64(public.as_bytes()),
        })
    }
}

/// A fresh curve25519 public key, base64 — everything `POST /reg` wants from the WireGuard side.
///
/// The private half is deliberately dropped on the floor: this device is a WireGuard one for
/// exactly one request, and keeping a key nobody will use would only invite the question of what
/// it is for.
pub fn generate_wireguard_public() -> String {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let public = x25519_dalek::PublicKey::from(&secret);
    super::api::b64(public.as_bytes())
}

/// The uncompressed SEC1 point of a P-256 public key, for logging and for comparing two keys
/// without decoding both.
pub fn public_point(secret: &p256::SecretKey) -> Vec<u8> {
    secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
