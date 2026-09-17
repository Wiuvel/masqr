//! The two commands run by hand to see whether a tunnel works on this link, and what stops it:
//! `probe` and `handshake`.
//!
//! Part of the binary, not the library. Nothing an application drives reaches them, and nothing
//! in them is used by `up`.

pub mod handshake;
mod packets;
pub mod probe;
