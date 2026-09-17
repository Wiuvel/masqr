//! Answering the machine's DNS, and turning what is answered into routing.
//!
//! This is the piece that makes routing follow names instead of a snapshot of addresses. Without
//! it the core can only carry what someone else resolved earlier, which is a losing race against
//! any content network: the address handed to the browser is rarely the address that was cached.
//!
//! The shape is a forwarder, not a resolver. A query is matched against a policy, sent to whichever
//! upstream that policy names, and the answer is returned exactly as it came back. What the core
//! keeps from the exchange is not the answer — Windows already caches that — but the addresses,
//! which become routes for as long as the answer says they are good for.

pub mod asker;
pub mod lease;
pub mod message;
pub mod policy;
pub mod server;
pub mod upstream;
