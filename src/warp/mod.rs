//! Everything that is specific to Cloudflare WARP: registering a device and knowing where its
//! tunnel is. The transport that carries the tunnel lives elsewhere — this module only produces
//! what the transport needs to start.

pub mod api;
pub mod enrolment;
pub mod identity;
pub mod keys;

pub use api::{ApiError, CONNECT_SNI, ENDPOINT_H2_V4, register};
pub use enrolment::{Enrolment, EnrolmentError, refusal_is_about_the_device};
pub use identity::{Identity, IdentityError};
