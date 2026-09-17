# Decisions

Five decisions shape everything else. Each was taken against a measurement, and each closed off an
alternative worth naming — the alternatives are the point of writing them down.

## 1. Only what is tunnelled enters the adapter

The adapter carries the addresses Cloudflare assigned and nothing else. Host routes point the
tunnelled destinations at it, so a packet arriving from Windows already carries the right source
address and needs no rewriting. Direct traffic never enters the adapter at all, so there is no second
network stack on this side and nothing to send back out.

**The alternative** is taking the default route, terminating every connection and recreating it
outbound. That is how a general-purpose proxy is built, and it is where the difficulty of one lives.
It buys the three things in [limits](limits.md) — at the price of becoming that program.

**The consequence that pays for itself.** Because the routes point at the *adapter* and not at the
connection, replacing a tunnel touches neither the adapter, nor its address, nor the route set. A
reconnect costs a fraction of a second, so it is affordable to be eager about finding a
dead tunnel: a false alarm is almost free, so the keepalive can be aggressive enough to notice a
hung tunnel within ten seconds. See [the tunnel](../architecture/tunnel.md#keeping-it-up).

## 2. The DNS lives here

Routing by address alone cannot follow a name. A content network hands the browser an address that
was in nobody's list, and the target leaves over the line. So the core answers the machine's queries
itself: each name is matched against a policy — which upstream answers it, and whether the answer
becomes routing — and the reply is returned exactly as it came back.

**What is kept is not the answer.** Windows already caches those; a second cache would give the
machine two opinions about one name. What is kept is the **addresses**, which become routes for as
long as the answer says they are good for and for as long after that as traffic keeps using them. An
address carrying traffic is never unrouted — taking a route from a live connection does not slow it,
it kills it, because the next packet leaves by another interface with another source address.

**Answering is only half of it; the machine has to *ask* here.** That is one name resolution policy
rule, written by the core, removed when it stops, and swept by a later run if it was killed. No
adapter is touched, so there is no configuration of the user's to record, to restore, or to get
wrong.

**And the rule is proved, not assumed.** The core asks the operating system to resolve a name it
invented and waits for it to arrive at its own listener. A takeover reported without having happened
is the one failure with no symptom of its own: names keep resolving, from somewhere else, and every
address they return is one the tunnel never hears about. See
[the machine's names](../architecture/names.md).

## 3. Programs can be pulled in, but not kept out

A query arrives from a port on the loopback, and Windows knows which program owns that port. So a
rule can say *when this program asks, the answer becomes routing*, and the program's traffic follows
the route like anyone else's.

Its failure mode is over-inclusion — another program asking the same name gets the same route —
which is the safe direction, and exactly what a rule about the name alone would have done.

**The opposite cannot be built this way.** To keep one program
out once the address is routed, its packets have to leave by another interface; they have already
arrived here, and sending them back out is termination or reinjection — decision 1, reversed. A
routing table decides by destination and by nothing else.

What *is* expressible is the mirror of the inclusion rule: a program's own questions can be answered
without routing the answers, so its traffic stays on the line. That reaches exactly as far as the
mechanism does, and no further — an address something else already routed is not taken back.

## 4. Dual-stack, with no opinion about which family wins

The adapter carries both assigned addresses from bring-up. A and AAAA are returned as they came;
amputating AAAA would be a hidden implementation of Happy Eyeballs, and racing the families is the
business of Windows and the browser, which see more than a tunnel does.

A v6 route is installed only when two things agree: whoever drives the core asked for IPv6, **and**
the tunnel was *measured* carrying it.

**Assuming instead is the one mistake that makes a working address family slower than it was before
the tunnel existed.** Nothing here resolves names on a program's behalf: the machine races the
families itself, on the strength of what the routing table says is reachable. Routing a v6 prefix
into a tunnel that does not carry v6 is telling Windows the faster-looking path exists, watching it
take that path, and letting it wait out its own fallback on every connection.

The measurement is asymmetric, deliberately:

- a measured **yes** is re-checked on every connect — one round trip — because a stale yes is the
  dangerous answer;
- a **no** is kept, because a stale no merely leaves v6 on the line, which is where it was anyway.
  It also spares every reconnect the full wait when there is no v6 to find.

Three states, not two: `Unknown` is a reason to ask, and `DoesNot` is an answer to keep.

## 5. HTTP/3 first, HTTP/2 behind it

The tunnel prefers CONNECT-IP over HTTP/3, where each packet is one QUIC datagram. Over HTTP/2 every
packet is bytes in one TCP stream: a loss holds up everything behind it, and the connections inside
the tunnel see delay where the path had loss. Measured on a filtered link, HTTP/3 to the endpoint
opened under a name the link does not act on and carried DNS round trips at 46–56 ms.

HTTP/2 stays, one step behind in the same attempt, because a link can drop UDP to the endpoint and
still carry TCP to it. On such a link HTTP/3's timeouts are paid once: HTTP/3 is then left alone
until the line changes, a reconnect is asked for, or ten minutes pass. See
[the tunnel](../architecture/tunnel.md#choosing).

**The alternatives.** HTTP/3 alone would lose every link that drops UDP; HTTP/2 alone keeps
TCP-over-TCP where it is not needed. And the HTTP/3 itself: the `h3` crate cannot express this
request — its `:protocol` values are a closed set, it adds `:scheme` and `:path` to a plain CONNECT,
and it has no way to send an extra setting — and quiche, which can, brings a second TLS stack and a
C toolchain. So QUIC is quinn, on the same rustls and ring as HTTP/2, and HTTP/3 is the small subset
written here: one request out, one response in, datagrams after. A dynamic table of zero is what
keeps that subset complete.
