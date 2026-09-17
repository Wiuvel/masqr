//! The registered device over time, rather than as written to disk.
//!
//! [`Identity`] is the file. This is what happens to it: loaded once, reused while the endpoint
//! accepts it, replaced when it stops. Without the last part, a device Cloudflare has invalidated
//! leaves the core presenting rejected credentials indefinitely, failing identically every few
//! seconds with nothing able to notice that the thing being retried cannot succeed.
//!
//! Replacement is deliberately narrow. Registering creates a real device on Cloudflare's side, so a
//! hunch leaves abandoned ones behind and a flapping link would leave one per flap. It happens on
//! one unambiguous signal — the endpoint refusing the request, not the network failing to carry
//! it — and no more often than [`MIN_INTERVAL`].

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use super::api::{ApiError, register};
use super::identity::{Identity, IdentityError};

/// The least time between one registration and the next.
///
/// A refusal that comes back inside this window is not a second invalidated device: it is the same
/// one, or something that is not about the device at all. Registering again would produce another
/// abandoned device and answer nothing.
pub const MIN_INTERVAL: Duration = Duration::from_secs(600);

#[derive(Debug, thiserror::Error)]
/// Why this machine has no usable device to open a tunnel with.
pub enum EnrolmentError {
    #[error("{0}")]
    Identity(#[from] IdentityError),
    #[error("registering a device: {0}")]
    Register(#[from] ApiError),
}

/// Why a fresh registration was not attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// One happened recently enough that this refusal is probably about the same thing.
    TooSoon,
}

/// The device this core presents, and the file it is kept in.
#[derive(Debug)]
pub struct Enrolment {
    path: PathBuf,
    /// Handed out by `Arc` so a connection attempt reads a consistent identity even if it is
    /// replaced while that attempt is in flight.
    current: RwLock<Arc<Identity>>,
    last: Mutex<Option<Instant>>,
}

impl Enrolment {
    /// Load the device kept at `path`, registering one if there is none.
    pub async fn load_or_register(path: &Path) -> Result<(Self, bool), EnrolmentError> {
        let (identity, registered) = match Identity::load(path)? {
            Some(identity) => (identity, false),
            None => {
                let identity = register().await?;
                identity.save(path)?;
                (identity, true)
            }
        };
        Ok((
            Self {
                path: path.to_path_buf(),
                current: RwLock::new(Arc::new(identity)),
                last: Mutex::new(None),
            },
            registered,
        ))
    }

    /// The device to present right now.
    pub fn current(&self) -> Arc<Identity> {
        Arc::clone(&self.read())
    }

    /// Register a new device because the endpoint refused the one held, and write it down.
    ///
    /// The new device is saved before it is adopted: a registration that succeeded and then failed
    /// to be written would leave a device existing on Cloudflare's side that nothing on this
    /// machine could ever present again.
    pub async fn refresh(
        &self,
        now: Instant,
    ) -> Result<Result<Arc<Identity>, Refused>, EnrolmentError> {
        if let Some(last) = *self.locked_last()
            && now.duration_since(last) < MIN_INTERVAL
        {
            return Ok(Err(Refused::TooSoon));
        }

        let identity = register().await?;
        identity.save(&self.path)?;
        let identity = Arc::new(identity);
        *self.write() = Arc::clone(&identity);
        *self.locked_last() = Some(now);
        Ok(Ok(identity))
    }

    /// Where the device is kept, for a message that has to name it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A poisoned lock holds an `Arc` to a device that was fully constructed before it was stored;
    /// nothing half-written can be in there. Refusing to hand it out would mean refusing to
    /// connect at all, which is a worse answer than carrying on with the device that works.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Arc<Identity>> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Arc<Identity>> {
        self.current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn locked_last(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Whether a refusal to open the tunnel is the endpoint declining this device.
///
/// A client error is the endpoint saying the request was wrong, and the only part of the request
/// that varies is who is making it: the shape is fixed and has worked. A server error is the
/// endpoint having a bad day, which registering a new device does not improve. Everything that is
/// not a refusal at all — a cut handshake, a dead link — is the network, and is the thing the
/// retry schedule already exists for.
pub fn refusal_is_about_the_device(status: http::StatusCode) -> bool {
    status.is_client_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    /// The whole of what decides whether a device is thrown away. Getting it wrong in one direction
    /// abandons a working device on every server hiccup; in the other it never notices an
    /// invalidated one.
    #[test]
    fn only_the_endpoint_declining_us_is_about_the_device() {
        for refused in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::BAD_REQUEST,
            StatusCode::GONE,
        ] {
            assert!(refusal_is_about_the_device(refused), "{refused}");
        }
        for elsewhere in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::OK,
            StatusCode::TEMPORARY_REDIRECT,
        ] {
            assert!(!refusal_is_about_the_device(elsewhere), "{elsewhere}");
        }
    }

    /// Registering creates a real device, so a burst of refusals must not create a burst of them.
    /// Checked without a network: the interval is decided before anything is registered.
    #[tokio::test]
    async fn a_second_refusal_too_soon_registers_nothing() {
        let directory = std::env::temp_dir().join("masqr-enrolment-test");
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let path = directory.join("identity.json");
        let _ = std::fs::remove_file(&path);

        let enrolment = Enrolment {
            path: path.clone(),
            current: RwLock::new(Arc::new(sample())),
            // As though one had just happened.
            last: Mutex::new(Some(Instant::now())),
        };

        let answer = enrolment
            .refresh(Instant::now())
            .await
            .expect("the interval is decided before the network is touched");
        // Compared on the refusal alone: an `Identity` has no meaningful equality, and asking for
        // one only to write an assertion would put it on the shipping type.
        assert_eq!(answer.err(), Some(Refused::TooSoon));
        assert!(!path.exists(), "nothing was written");
    }

    fn sample() -> Identity {
        Identity {
            device_id: "device".into(),
            access_token: "token".into(),
            license: String::new(),
            private_key_sec1: String::new(),
            endpoint_public_key_pem: String::new(),
            assigned_v4: "172.16.0.2".into(),
            assigned_v6: "2606:4700::1".into(),
            endpoint_h2_v4: "162.159.198.2".into(),
            endpoint_v4: "162.159.198.1".into(),
            endpoint_v6: String::new(),
        }
    }
}
