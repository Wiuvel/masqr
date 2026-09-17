//! A MASQUE/WARP tunnel core for Windows: one transport, one platform, one adapter.
//!
//! **An answer is a route.** A routing table decides by destination, so following a *name* means
//! being what answered it. The resolver here returns an address and points that address at the
//! adapter in the same step. Nothing needs resolving in advance, and a CDN handing out an address
//! nobody listed is still carried.
//!
//! Three consequences:
//!
//! * The adapter carries only tunnelled traffic. Direct traffic never enters it, so there is no
//!   second network stack.
//! * Routes point at the adapter, not at the connection. Replacing a tunnel moves neither the
//!   adapter, its address, nor any route, so a reconnect costs a fraction of a second — which is
//!   what makes an eager liveness check affordable.
//! * A program can be pulled into the tunnel (a rule can route what it resolves) but not kept out:
//!   by then the address is routed for every process.
//!
//! ```text
//!            Windows                                        Cloudflare
//!               │                                                │
//!   names       │  packets                                       │
//!      ┌────────┴────────┐                                       │
//!      ▼                 ▼                                       │
//!   [dns] ──leases──► [core] ◄──routes── [tun]                    │
//!      │                 ▲                                       │
//!      │              [engine] ──► [transport] ──CONNECT-IP──────┘
//!      │                 ▲
//!      └── [control] ────┘   policy, routed set, log level, stop
//! ```
//!
//! * [`tun`] — the Wintun adapter, its addresses and its routes. Windows removes both when this
//!   process ends.
//! * [`core`] — the routed set, and the lock keeping its two halves (asked for, and learned from
//!   DNS) consistent.
//! * [`dns`] — the resolver the machine talks to: which upstream answers, and whether the answer
//!   becomes a route. [`names`] is what points the machine here.
//! * [`queue`] — flow queueing and CoDel between the adapter and the tunnel.
//! * [`transport`] — the MASQUE leg: CONNECT-IP over HTTP/3 (QUIC datagrams) or HTTP/2 (a capsule
//!   stream), TLS from the enrolled identity under both.
//! * [`engine`] — keeping a tunnel up and pumping packets, including detecting a connection left
//!   hanging by a link that went away.
//! * [`warp`] — device registration, reuse and replacement.
//! * [`control`] — the named pipe, one JSON object per line.
//! * [`link`] — interface-change notifications from Windows.
//! * [`probe`] — measurements that must not be assumed, chiefly IPv6 carriage.
//! * [`log`] — one line per event, at a level changeable on a live tunnel.
//!
//! `docs/` carries the decisions, the control protocol and the known limits.

#[macro_use]
pub mod log;

pub mod control;
pub mod core;
pub mod dns;
pub mod engine;
pub mod ip;
pub mod link;
pub mod names;
pub mod probe;
pub mod queue;
pub mod transport;
pub mod tun;
pub mod warp;
