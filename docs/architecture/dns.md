# DNS

The piece that makes routing follow names instead of a snapshot of addresses. Without it the core
can only carry what someone else resolved earlier, which is a losing race against any content
network: the address handed to the browser is rarely the address that was cached.

Code: `src/dns/`.

## A forwarder, not a resolver

A query is matched against a policy, sent to whichever upstream that policy names, and the answer is
returned **exactly as it came back** — records, flags, order, all untouched. This is not the thing
that knows what a name means.

What the core keeps from the exchange is not the answer (Windows already caches that; a second cache
would give the machine two opinions about one name) but the **addresses**, which become routes.

There is exactly one message the resolver ever writes, and it writes it by editing the query's own
header rather than by building anything: the failure reply. A forwarder that cannot reach an
upstream has to say so — dropping the query instead would leave the machine waiting out its own
timeouts with no other resolver to try, because this is the only one it has.

It listens on **UDP and TCP**, because the protocol requires both and because the answers that need
TCP are exactly the large ones a content network gives.

| Bound | Value | Why |
| ----- | ----- | --- |
| `MAX_IN_FLIGHT` | 512 | Queries being answered at once. |
| `MAX_MESSAGE` | 65535 | The protocol's own ceiling. |
| `TCP_IDLE` | 30 s | How long an idle TCP connection is held. |

## Reading messages

`src/dns/message.rs` reads DNS messages and **never builds one**. That is a decision rather than an
omission: this core forwards queries and returns the answer it was given, byte for byte. Half a
serialiser is how a forwarder starts quietly rewriting what it passes on.

Everything is bounds-checked and every loop is bounded. A DNS message arrives from the network before
anything has been decided about it, so a malformed one has to be an error and never a panic — and
the two shapes that make that hard, compression pointers and label lengths, are the two the module
is most careful about.

## The policy

Data, handed over the control interface and **replaced whole**. Never edited in place and never
merged: an application that can only say "this is the policy now" cannot leave the core holding half
of an old one, and a reader never sees a set that existed at no point in time.

**First match wins**, and the order is the application's.

Each rule says two things, and they are deliberately separate:

- **which upstream answers** — and which side of the tunnel that upstream is asked from (`via`). A
  resolver reached through the tunnel sees the exit's location; one reached directly sees the line's.
  See [upstreams](#upstreams) for how each is kept.
- **whether the answers become routing** (`route`). "Ask through the tunnel" and "send the traffic
  through the tunnel" are different questions, and a scoped resolver that hands back a front address
  is exactly the case where they differ.

**Matching is by label, not by text.** A suffix rule for `example.com` covers `example.com` and
`a.example.com`, and does **not** cover `notexample.com`.

A policy is validated when it is installed, not on the first query it decides — the previous policy
is still in place, and a machine answering names by yesterday's rules is a working machine. It is
refused for: a rule naming an undeclared resolver, a resolver declared twice, a rule matching an
empty name, or a DoH resolver with no URL. See
[control pipe → `dns`](../reference/control-pipe.md#dns).

## Leases

The cache the DNS side keeps — deliberately not a cache of answers, but of which addresses were
handed out and for how long they may be believed.

Two rules keep the table honest, and both exist because of the same hazard: taking a route away from
a connection using it does not merely slow that connection down. The next packet leaves by another
interface with another source address, and the connection is dead. So:

- a lease lasts at least **`MIN_LEASE` (10 min)**, however short the record's own TTL. A content
  network hands out records that live thirty seconds, which describes how long its answer is worth
  trusting, not how long a download takes;
- a lease is renewed by **use**, not only by another answer — the packet path touches the expiry
  through an atomic, so renewing needs only a shared borrow;
- and no lease outlives **`MAX_LEASE` (1 h)**, whatever a record claims. A day-long TTL is a
  statement about a name, not a licence to pin an address for a day.

Together: an address carrying traffic is never unrouted, and an address nobody has used since its
record expired does not stay pinned for the rest of the session.

`MAX_LEASES` (8192) bounds the table. Without it, a stream of answers naming fresh addresses would
grow the machine's routing table without limit, and nothing in the protocol stops one.

One address may be held by several names — two names on one content network share addresses
constantly — which is why a lease cannot be dropped just because one of its names expired.

## Which program asked

A query arrives as a datagram from a port on loopback, and Windows knows which process owns that
port. That is the whole mechanism (`src/dns/asker.rs`), and it is worth being precise about what it
buys.

It does **not** let the core route by process — a routing table decides by destination and nothing
else. What it lets a policy say is *when this program asks, the answer becomes routing*, and the
program's traffic then follows the route like anyone else's.

The failure mode is **over-inclusion**: another program asking the same name gets the same route.
That is the safe direction, and exactly what a rule about the name alone would already have done.
The opposite — keeping one program out while others are let in — cannot be built this way and is not
attempted here.

A rule names a program by **file name or by full path**, because an application writes whichever it
has: a list of base programs is written as file names, a program the user picked is written as the
path they picked.

Two caches, for two different reasons: the table of ports is re-read on a short timer
(`TABLE_TTL`, 1 s) because it changes constantly and reading it costs a pair of system calls; a
process's own image path never changes, so that is remembered (up to `MAX_IMAGES`, 512) until the
table stops mentioning it.

## Upstreams

A query is forwarded byte for byte and the reply is returned byte for byte. Nothing in
`src/dns/upstream.rs` builds or rewrites a message; the only thing read out of a reply before it is
passed on is enough of the header to be sure it belongs to the query.

Two transports, and the difference between them is not how they are dialled but what a filtered line
can do to them:

- **Plain** DNS is readable and forgeable in flight, which is why an application keeps a resolver on
  it only for names it is content to expose. UDP, with TCP as the fallback the protocol requires.
- **DoH** is neither, which is why everything that matters goes over it. The resolver is declared
  with an address *and* a URL: the address is what is dialled, and the name in the URL is what the
  certificate is checked against.

A resolver is always declared by **address, never by name** — a resolver that had to be resolved
first is a resolver that cannot answer the first question of a session.

**Which side a query leaves by.** A resolver declared as reached through the tunnel is reached that
way because its address is routed there, and it is asked with an ordinary socket.

A resolver declared as reached directly is asked **from the line's own address** for it. Its address
being routed into the tunnel does not change that. An application routes the public resolvers'
addresses in so a browser's own secure DNS is carried, and those are often the very resolvers the
policy names for answers that have to come from the machine's side. Windows sends with the strong
host model: a socket bound to an address only takes routes on the interface that owns it, and the
host route into the adapter is not one of them.

The line's address for a destination is found the way the stack itself picks a route, with this
core's adapter left out: longest prefix, then lowest metric (route plus interface), among connected
interfaces. The stack then names the source address on that interface (`src/tun/outside.rs`). A
resolver behind a VPN is therefore asked by the VPN's route, not by the default one. The lookup walks
the routing table, so each answer is kept until the line changes, and at most for 30 s. When no
interface but the adapter has a route, the query goes wherever the routing table sends it.

A DoH client dials from one address for its life. When the line's address changes, the client is
replaced, and its pool and TLS session with it.
