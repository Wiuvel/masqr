//! Carrying IP packets to Cloudflare: CONNECT-IP over HTTP/3 or HTTP/2, the framing each one needs,
//! and the TLS session both run inside.

pub mod capsule;
pub mod carrier;
pub mod connect_ip;
pub mod handshake;
pub mod http3;
pub mod huffman;
pub mod qpack;
pub mod quic;
pub mod tcp;
pub mod tls;
pub mod varint;

pub use carrier::{Carrier, Choice};
pub use connect_ip::{
    ConnectError, LinkStats, Stages, Tunnel, TunnelHealth, TunnelReceiver, TunnelSender, connect,
    connect_h3,
};
pub use handshake::Handshake;
