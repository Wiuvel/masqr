//! The Cloudflare consumer-WARP registration API.
//!
//! Registering turns a fresh install into something that can open a MASQUE tunnel: it returns a
//! device identity, the addresses the tunnel will carry, and the endpoint public key the TLS
//! handshake is verified against.
//!
//! Two calls, and the order is forced. `POST /reg` accepts only a **curve25519** key — the
//! WireGuard shape — so a device is always born as a WireGuard one. `PATCH /reg/{id}` then enrolls
//! a **P-256** key, switches the tunnel type to MASQUE, and only its response carries the endpoint
//! public key. The first key is never used again.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::identity::Identity;
use super::keys::MasqueKeyPair;

/// The API this speaks. Pinned: the path carries the version, and a different one is a different
/// contract, not a newer one.
const API_URL: &str = "https://api.cloudflareclient.com";
const API_VERSION: &str = "v0a4471";

/// The HTTP/2 endpoint the data path dials over TCP.
///
/// A constant, not a name: the MASQUE connection goes to a literal address, so the tunnel needs no
/// DNS of its own to come up. The API does not return this one — the peer endpoints it hands back
/// are the UDP ones — so it is known the way Cloudflare's own clients know it.
pub const ENDPOINT_H2_V4: &str = "162.159.198.2";

/// The HTTP/3 endpoint, over UDP: what registration returns as the peer's endpoint.
///
/// Used when the identity on disk predates this core keeping that address. It is one anycast
/// address for every consumer device rather than something allotted to this one, so an older
/// identity loses nothing by it and does not need registering again.
pub const ENDPOINT_H3_V4: &str = "162.159.198.1";

/// The SNI the MASQUE handshake presents.
pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";

/// What the client says it is. The API answers differently to clients it does not recognise, so
/// these are part of the protocol rather than decoration.
const USER_AGENT: &str = "WARP for Android";
const CLIENT_VERSION: &str = "a-6.35-4471";

#[derive(Debug, thiserror::Error)]
/// Why a call to the endpoint's registration interface did not produce an answer.
pub enum ApiError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{call} returned {status}")]
    Status { call: &'static str, status: u16 },
    #[error("the enrolled profile carries no peer to connect to")]
    NoPeer,
    #[error("key: {0}")]
    Key(#[from] super::keys::KeyError),
}

#[derive(Serialize)]
struct RegisterRequest {
    key: String,
    install_id: &'static str,
    fcm_token: &'static str,
    tos: String,
    model: &'static str,
    serial_number: String,
    os_version: &'static str,
    key_type: &'static str,
    tunnel_type: &'static str,
    locale: &'static str,
}

#[derive(Serialize)]
struct EnrollRequest {
    key: String,
    key_type: &'static str,
    tunnel_type: &'static str,
    name: &'static str,
}

/// Only the fields this core reads. The API returns a great deal more — account plan, referral
/// counters, waitlist state — and none of it decides anything here.
#[derive(Deserialize)]
struct Profile {
    id: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    account: Account,
    #[serde(default)]
    config: ProfileConfig,
}

#[derive(Deserialize, Default)]
struct Account {
    #[serde(default)]
    license: String,
}

#[derive(Deserialize, Default)]
struct ProfileConfig {
    #[serde(default)]
    peers: Vec<Peer>,
    #[serde(default)]
    interface: Interface,
}

#[derive(Deserialize, Default)]
struct Interface {
    #[serde(default)]
    addresses: Addresses,
}

#[derive(Deserialize, Default)]
struct Addresses {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

#[derive(Deserialize)]
struct Peer {
    /// PEM once the enrolled key is P-256 — this is what the endpoint's certificate is checked
    /// against, over either transport.
    public_key: String,
    /// Where HTTP/3 goes. Written with a placeholder port: `162.159.198.1:0`, `[2606:…]:0`.
    #[serde(default)]
    endpoint: PeerEndpoint,
}

#[derive(Deserialize, Default)]
struct PeerEndpoint {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

/// The address out of an endpoint the API writes as `address:port`, with the port dropped.
///
/// Parsed rather than trimmed: the v6 form is bracketed, and a trim written for the placeholder
/// `:0` would take the wrong bytes the day the API writes a real port. Anything that does not parse
/// is left empty, and the identity then falls back to the known address.
fn endpoint_address(written: &str) -> String {
    written
        .parse::<std::net::SocketAddr>()
        .map(|address| address.ip().to_string())
        .unwrap_or_default()
}

/// Register a fresh device and enroll a MASQUE key for it.
///
/// The returned identity is a real credential for a real device on Cloudflare's side. It is cached
/// and reused; registering on every start would create a new device each time.
pub async fn register() -> Result<Identity, ApiError> {
    let client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    // Step one: be born as a WireGuard device, because that is the only shape `/reg` accepts.
    let wg_public = super::keys::generate_wireguard_public();
    let profile: Profile = send(
        "register",
        client
            .post(format!("{API_URL}/{API_VERSION}/reg"))
            .json(&RegisterRequest {
                key: wg_public,
                install_id: "",
                fcm_token: "",
                tos: now_as_cloudflare_string(),
                model: "PC",
                serial_number: random_serial(),
                os_version: "",
                key_type: "curve25519",
                tunnel_type: "wireguard",
                locale: "en-US",
            }),
    )
    .await?;

    // Step two: swap in the key the tunnel will actually use. Only this response carries the
    // endpoint public key.
    let keys = MasqueKeyPair::generate()?;
    let enrolled: Profile = send(
        "enroll",
        client
            .patch(format!("{API_URL}/{API_VERSION}/reg/{}", profile.id))
            .bearer_auth(&profile.token)
            .json(&EnrollRequest {
                key: keys.public_spki_base64.clone(),
                key_type: "secp256r1",
                tunnel_type: "masque",
                name: "PC",
            }),
    )
    .await?;

    let peer = enrolled.config.peers.first().ok_or(ApiError::NoPeer)?;
    Ok(Identity {
        device_id: enrolled.id,
        access_token: profile.token,
        license: enrolled.account.license,
        private_key_sec1: keys.private_sec1_base64,
        endpoint_public_key_pem: peer.public_key.clone(),
        assigned_v4: enrolled.config.interface.addresses.v4,
        assigned_v6: enrolled.config.interface.addresses.v6,
        endpoint_h2_v4: ENDPOINT_H2_V4.to_string(),
        endpoint_v4: endpoint_address(&peer.endpoint.v4),
        endpoint_v6: endpoint_address(&peer.endpoint.v6),
    })
}

/// Send one request and decode it, turning a non-200 into an error that names which call failed.
async fn send<T: for<'de> Deserialize<'de>>(
    call: &'static str,
    request: reqwest::RequestBuilder,
) -> Result<T, ApiError> {
    let response = request
        .header("CF-Client-Version", CLIENT_VERSION)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(ApiError::Status {
            call,
            status: status.as_u16(),
        });
    }
    Ok(response.json().await?)
}

/// Eight random bytes as hex — the shape the API expects of an Android serial.
fn random_serial() -> String {
    use rand::RngCore as _;
    let mut serial = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut serial);
    hex::encode(serial)
}

/// The timestamp format the API's terms-of-service field is written in: milliseconds and a numeric
/// offset, e.g. `2026-08-31T00:12:34.567+02:00`.
fn now_as_cloudflare_string() -> String {
    chrono::Local::now()
        .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
        .to_string()
}

/// Base64 with the standard alphabet and padding, which is what every field here is encoded in.
pub(super) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both forms the API writes the peer endpoint in: a v4 address and a bracketed v6 one, each
    /// with a placeholder port.
    #[test]
    fn the_peer_endpoint_is_read_without_its_port() {
        assert_eq!(endpoint_address("162.159.198.1:0"), "162.159.198.1");
        assert_eq!(endpoint_address("[2606:4700:103::1]:0"), "2606:4700:103::1");
    }

    /// Anything else is left empty, which makes the identity fall back to the known address rather
    /// than dial something half-read.
    #[test]
    fn an_endpoint_that_does_not_parse_is_left_empty() {
        assert_eq!(endpoint_address(""), "");
        assert_eq!(endpoint_address("162.159.198.1"), "");
        assert_eq!(endpoint_address("not an address:0"), "");
    }
}
