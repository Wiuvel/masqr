//! The registered device, as it is kept between runs.
//!
//! Registering creates a real device on Cloudflare's side, so it happens once and the result is
//! reused. A core that registered on every start would leave a trail of abandoned devices and
//! would spend two network round-trips before it could begin.
//!
//! The file format is this core's own. It is deliberately not sing-box's config shape — nothing
//! reads it but this core — but the private key uses the same SEC1 encoding, so an identity is
//! portable between the two implementations while both exist.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
/// Why the device on disk could not be read or written.
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
/// A registered device: who this machine is to the endpoint, and where the tunnel goes.
///
/// The one thing this core persists. It is read at start and reused; registration happens once.
pub struct Identity {
    /// The device's id on Cloudflare's side; the path component of every later call.
    pub device_id: String,
    /// Bearer token for those calls. A credential — see the repository's ignore list.
    pub access_token: String,
    /// Empty for a free account; carried so an account that has a plan keeps it across a re-read.
    #[serde(default)]
    pub license: String,
    /// The MASQUE private key, SEC1 DER in base64. Signs the client certificate.
    pub private_key_sec1: String,
    /// The endpoint's public key, PEM. The TLS handshake is verified against this rather than
    /// against a certificate authority: the endpoint presents its own key, not a chain.
    pub endpoint_public_key_pem: String,
    /// The addresses the tunnel carries — the inside of the tunnel, not the machine's.
    pub assigned_v4: String,
    pub assigned_v6: String,
    /// Where the HTTP/2 data path dials. A literal address, so bringing the tunnel up needs no DNS.
    pub endpoint_h2_v4: String,
    /// Where HTTP/3 goes, as registration returned it. Empty in an identity written before this
    /// core kept it — see [`Identity::endpoint_h3_v4`], which is what reads it.
    #[serde(default)]
    pub endpoint_v4: String,
    #[serde(default)]
    pub endpoint_v6: String,
}

impl Identity {
    /// The HTTP/3 endpoint to dial: the one registration returned, or the known anycast address
    /// when this identity was written before that was kept.
    pub fn endpoint_h3_v4(&self) -> &str {
        if self.endpoint_v4.is_empty() {
            super::api::ENDPOINT_H3_V4
        } else {
            &self.endpoint_v4
        }
    }

    /// Read the device from disk, or nothing when this machine has none yet.
    pub fn load(path: &Path) -> Result<Option<Self>, IdentityError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
            // A missing file is the ordinary first-run case, not a failure.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Write the device to disk, creating the directory it lives in.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An identity written before the HTTP/3 address was kept. Every device registered until then
    /// has one of these on disk, and it has to keep working without registering again.
    const WRITTEN_BEFORE: &str = r#"{
        "device_id": "device",
        "access_token": "token",
        "private_key_sec1": "",
        "endpoint_public_key_pem": "",
        "assigned_v4": "172.16.0.2",
        "assigned_v6": "2606:4700::1",
        "endpoint_h2_v4": "162.159.198.2"
    }"#;

    #[test]
    fn an_older_identity_still_reads_and_dials_the_known_address() {
        let identity: Identity = serde_json::from_str(WRITTEN_BEFORE).expect("the old shape reads");
        assert_eq!(identity.endpoint_v4, "");
        assert_eq!(identity.endpoint_h3_v4(), super::super::api::ENDPOINT_H3_V4);
    }

    #[test]
    fn the_address_registration_returned_wins_over_the_known_one() {
        let mut identity: Identity =
            serde_json::from_str(WRITTEN_BEFORE).expect("the old shape reads");
        identity.endpoint_v4 = "198.51.100.7".into();
        assert_eq!(identity.endpoint_h3_v4(), "198.51.100.7");
    }
}
