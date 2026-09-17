# Limits

What this core does not do. Each is a decision with a reason, not a gap waiting to be filled — and
each is the direct consequence of a [decision](decisions.md) that buys something else.

## Three things a general-purpose proxy can do

### Keep a program out of the tunnel

A routing table decides by destination. Once an address is routed, it is routed for everything on the
machine.

What *can* be said is the near mirror: a program's own questions are answered without routing the
answers, so its traffic stays on the line. That covers the ordinary case — a program that reaches its
own services by name — and does not cover the case where something else already routed the same
address.

### Recover a name from a connection opened to a literal address

Names are known here from having been *answered*. A connection that never asked carries none, so
there is nothing to match a rule against.

An engine that terminates connections can read the SNI out of a TLS handshake and recover the name
that way. This one never sees the handshake — it moves IP packets.

### Decide by port

Same reason as the first. The name half of such a rule is expressible and is used — a host answered
by the machine's own resolver is never leased, so its address is not routed — but a server whose
address falls inside a routed range is routed by that address, and a port cannot stop it.

---

All three want the same thing: **the default route in the adapter, a flow table, and terminated
connections.** That is a different program, and it is the program this one exists not to be.

## Ranges that have not been narrowed

Not a lack, but worth stating because it looks like one from outside.

Large provider or CDN address sets are only usable here after being intersected with something that
says which parts of them matter. A narrowed set is a handful of ranges; the set itself is thousands,
and one cloud provider alone is over a thousand prefixes. The core routes by address and puts a row
in the machine's routing table per prefix, so putting a whole set there is worse than leaving it out.

Narrowing is the application's job, not the core's — the core takes prefixes and carries them. What
the core does is not pretend: a set that reaches it as nothing is a set that carries nothing, and
whoever drives it can say so rather than showing it as enabled.

## Not a proxy platform

No protocol zoo, no configuration compatibility with anything, no cross-platform ambitions.

One protocol (MASQUE, over HTTP/3 on UDP/443 or HTTP/2 on TCP/443), one platform (Windows), one
adapter (Wintun), and a routing policy shaped by what is actually asked for. It exists to be the tunnel one application
needs, and to be small enough that its whole behaviour fits in one person's head.

## Two costs that are accepted, not solved

**TCP-over-TCP, where HTTP/3 does not open.** Over HTTP/2 the tunnel carries mostly TCP traffic
inside TCP; on packet loss both stacks retransmit and throughput drops. HTTP/3 removes it, and the
tunnel prefers HTTP/3 — but on a link that drops UDP to the endpoint, HTTP/2 is what carries, and
there the cost is the price of a tunnel that connects.

**The handshake is not a browser's.** WARP authenticates by a client certificate over the enrolled
key, and browsers do not send client certificates. "Indistinguishable from a browser" is unreachable
in principle here; only "less characteristic" is on the table. What *was* reachable is the name: the
endpoint turns out not to route by it, so the tunnel presents one the link does not act on — see
[`--handshake`](../reference/cli.md#--handshake-mode).
