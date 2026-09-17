# Testing

```powershell
cargo test
```

190 tests across the library and the binary. They run in well under a second, because nothing in
them waits on a network — the ones that need a peer make their own on loopback.

## What the tests are for

The parts worth testing here are the ones where being wrong looks exactly like being right. A
protocol parser that mis-reads a length, a filter that lets through what it exists to stop, a call
into Windows that returns nothing rather than an error — none of those raise their hand.

So the tests cluster where that is true:

| Module | What is pinned |
| ------ | -------------- |
| `dns::message` | Reading messages that arrive from the network before anything has decided about them: compression pointers, label lengths, truncation. A malformed message has to be an error and never a panic. |
| `dns::policy` | The order rules are consulted in, label-boundary matching, and every refusal a bad policy earns. First match wins, so a rule in the wrong place is not a smaller effect — it is a different one. |
| `dns::lease` | The minimum and maximum a lease may last, renewal by use, and the bound on how many are held. |
| `dns::asker` | Which program a query came from, and that an unknown one matches no rule about programs. |
| `transport::varint` | QUIC variable-length integers across every length class, and RFC 9000's worked examples. |
| `transport::capsule` | Capsule framing over HTTP/2, both directions, and the ceiling on a declared length. |
| `transport::huffman` | RFC 7541's examples, every byte value round-tripped, and the padding rules — plus that the table is canonical, which the decoder's arithmetic assumes. |
| `transport::qpack` | The CONNECT request byte for byte, every form a response may take without a dynamic table, and every dynamic reference refused. |
| `transport::http3` | Frames split across reads, unknown frames skipped without being buffered, the control stream's rules, SETTINGS, and the datagram layout. |
| `transport::quic` | The HTTP/3 carrier end to end against a stand-in endpoint on loopback: the pinned key, SETTINGS both ways, the request as the endpoint reads it, a packet out and back, a refusal, and GOAWAY. |
| `transport::carrier` | Which carrier an attempt tries for every choice and handshake, and how long HTTP/3 stays parked. |
| `queue` | Flow fairness, CoDel's drops and marks, acknowledgement thinning, and that what waited out a gap between tunnels is dropped without leaving the next one dropping too. |
| `diagnose::packets` | The echo and DNS packets `handshake` and `probe` build by hand: checksums that verify, and a reply read only when it answers this run. |
| `link` | The filter that keeps the core's own route writes from coming back as reasons to check the tunnel. |
| `tun` | Prefix parsing, and that applying the same route set twice moves nothing. |
| `log` | That the levels compare in the order they are declared — reordering the enum without noticing would silently change what is printed. |

## The tests written against Windows, not against a description of it

A handful deliberately call the real operating system, because the failure mode of getting one of
these calls wrong is that it compiles and then quietly does nothing:

- **`names`** — the registry enumeration and reading the sweep depends on, exercised against a key
  every Windows has and every account can read. A wrong call there returns an empty answer rather
  than an error, which in release would mean sweeping nothing and reporting that there was nothing
  to sweep.
- **`names`** — that `dnsapi.dll` actually exposes `DnsFlushResolverCache`. If the entry point is not
  there, a policy change would appear to work and decide nothing for as long as the old answers live.
- **`link`** — that registering for interface-change notifications succeeds and cancels cleanly.

These are the tests that would be worthless as mocks: a mock of a call you got wrong agrees with you.

## What tests cannot reach

Three things are only true on a machine, and no unit test observes them:

- **That the tunnel carries traffic.** `masqr probe` is the check: it opens the tunnel and resolves
  one name through it, which proves the identity, the CONNECT-IP negotiation, the framing and the
  routing at Cloudflare's end in a single exchange — over whichever carrier `--transport` asks for.
- **That traffic from Windows itself goes through it.** `masqr up` with a routed prefix, then an
  ordinary request to an address in it — from a program that knows nothing about any of this.
- **That a stop leaves nothing behind.** Bring-up and teardown with requests in flight, repeatedly,
  checking after each one that the process exited with **zero**, that no adapter of ours is left, that
  no name policy rule of ours is left, and that no route points at an adapter that is gone.

The third is the one where the defects have actually been. A crash on the way out looks, from
outside, exactly like a status code in the billions — see
[the shutdown contract](../architecture/adapter.md#the-shutdown-contract), which was found by running
that loop and watching it fail fifty times out of fifty.

All three need the endpoint to be reachable; on a filtered line that means a handshake the line does
not act on — `fronted`, the default — or the handshake is cut before anything else can be observed.
`up` additionally needs to be elevated.
