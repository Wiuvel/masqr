# The tunnel

How a device becomes able to open a tunnel, what the tunnel is made of, and what keeps it up.

Code: `src/warp/`, `src/transport/`, `src/engine.rs`, `src/link.rs`.

## Registering a device

Registration turns a fresh install into something that can open a MASQUE tunnel. It takes two
calls, and the order is not arbitrary:

1. **`POST /reg`** accepts a **curve25519** key — the WireGuard shape — and nothing else. So a
   device is always born as a WireGuard one. This is the only thing that key pair is ever used
   for; neither half is touched again.
2. **`PATCH /reg/{id}`** enrols a **P-256** key and switches the tunnel type to MASQUE. Only the
   response to *this* call carries the endpoint public key the TLS handshake is later verified
   against.

What comes back is written to [`identity.json`](../reference/identity.md) and reused for as long as
the endpoint accepts it. Registering creates a real device on Cloudflare's side, so it happens once:
a core that registered on every start would leave a trail of abandoned devices and would spend two
network round trips before it could begin.

Registration is the only thing in the core that talks to a *name* (`api.cloudflareclient.com`).
Everything after it dials a literal address — HTTP/3's from the registration response, HTTP/2's a
constant every client knows — so bringing a tunnel up needs no DNS.

### Replacing a refused device

A device Cloudflare has invalidated would otherwise leave the core presenting the same rejected
credentials forever, failing identically every few seconds, with nothing in the retry loop able to
notice that the thing being retried is the one thing that cannot succeed.

So `warp::Enrolment` replaces it — narrowly:

- the sign is a **4xx from the endpoint** and nothing else. A refusal carried by a dead line belongs
  to the network, which is what the backoff schedule allows for;
- and no sooner than **ten minutes** after the last registration, so a flapping link cannot create
  one device per flap.

After replacing it the core **stops** rather than carrying on. New credentials come with new
addresses inside the tunnel, and changing an interface's address underneath a running core is a
great deal of care for an event that happens approximately never.

## The TLS session

Two things about it are unusual, and both follow from how WARP proves who is calling:

- **The client presents a certificate.** It is self-signed with the P-256 key registration enrolled,
  and that enrolment *is* the authentication: the endpoint recognises the key, not a name and not a
  chain. This is also why the handshake can never be made to look exactly like a browser's —
  browsers do not send client certificates.
- **The server is not checked against a certificate authority.** The endpoint answers with its own
  certificate, and registration already told us which public key it should carry. Comparing that key
  is a stronger statement than a chain to a public root would be, and it is the only check that
  makes sense for a certificate no authority ever signed.

The same session runs under both carriers — over TCP for HTTP/2, inside QUIC for HTTP/3 — and offers
exactly the one protocol its carrier speaks in ALPN.

Code: `src/transport/tls.rs`.

## Two carriers

The tunnel is CONNECT-IP to the same endpoint under the same identity, over one of two carriers:

| | HTTP/3 | HTTP/2 |
| --- | --- | --- |
| Under it | QUIC on UDP/443 | TLS on TCP/443 |
| Address | the one registration returns as the peer's endpoint | a constant every client knows |
| A packet travels as | one QUIC datagram | a capsule in the request body |
| A lost packet | is lost to the connection inside that sent it | holds up every packet behind it until TCP resends it |
| Liveness | anything heard from the endpoint, which QUIC's keep-alive guarantees | an HTTP/2 ping |
| The round trip the queue works to | QUIC's estimate from acknowledgements | the ping's, which waits behind the TCP send buffer |

HTTP/3 is preferred, and HTTP/2 carries where HTTP/3 does not open. Code: `src/transport/carrier.rs`,
`quic.rs`, `tcp.rs`, and `connect_ip.rs` — the one interface the engine drives either through.

### HTTP/3

Extended CONNECT with `:protocol = cf-connect-ip` — Cloudflare's token; RFC 9484's `connect-ip` is
refused with 403 — plus `capsule-protocol: ?1` and an empty user agent. Each IP packet is then one
QUIC datagram, `varint(stream id / 4) · 0 · packet`: the request stream's quarter id, then
CONNECT-IP's context id for a whole packet. Replies arrive the same way.

What the endpoint requires beyond the RFCs was measured against it, and matches the two working
third-party clients:

- connection ids of 20 bytes — shorter ones are refused now and then with `PROTOCOL_VIOLATION`;
- SETTINGS carrying `H3_DATAGRAM` under its RFC identifier (`0x33`) and its draft-00 one (`0x276`);
- nothing written on the request stream after the request — a capsule written there got the stream
  reset;
- a name in the Initial that the link does not act on. WARP's own name and no name at all both get
  the handshake through and then the CONNECT left unanswered; `fronted` carries. The ClientHello in a
  QUIC Initial is readable on the way, because the Initial's keys come from the packet itself.

A packet has to fit one datagram. The handshake runs at QUIC's floor of 1200 bytes, where a datagram
holds 1150 — less than the adapter's 1280 — and path MTU discovery raises the room within a couple of
round trips. The tunnel is handed over only once a full packet fits; a path that never gets there is
unfit for HTTP/3, and HTTP/2 carries. If the room shrinks later — discovery finding a black hole —
the tunnel ends rather than lose every full-size packet, and the next attempt decides again.

HTTP/3 itself is written here rather than taken from a crate: `http3.rs` (frames, SETTINGS, the
control stream's rules, the datagram layout), `qpack.rs` (static-table QPACK: the request as plain
literals, the response in any form that needs no dynamic table) and `huffman.rs`. Declaring a dynamic
table of zero is what makes a subset this small complete: no QPACK streams, and nothing on one stream
waiting on another's state. QUIC is quinn, on the same rustls and ring as the HTTP/2 leg.

### HTTP/2

The shape is Cloudflare's, not RFC 9484's: a plain HTTP/2 `CONNECT` to `cloudflareaccess.com` with
two headers naming the protocol (`cf-connect-proto: cf-connect-ip`, `pq-enabled: false`), and the
request body becomes the capsule stream. Once the response is `200`, capsules written into the
request body carry packets out, and capsules read from the response body carry them back.

The price is TCP-over-TCP, and it is not merely a lower ceiling — it removes a signal:

> The outer TCP delivers everything reliably, so the TCP connections *inside* the tunnel never see
> loss. They never back off. They see only the delay growing, and they keep pushing.

What answers that is the queue in front of the tunnel, not the transport. See
[the queue](#the-queue), which drops on standing delay for exactly this reason.

Two things follow that are easy to get wrong. Several HTTP/2 *streams* would not help: the
head-of-line blocking is in the TCP byte stream underneath them, so they all stall together. And
several TCP *connections* would help throughput and cost more than they are worth here — each one
is a new flow for a DPI to classify, and the handshake this core relies on works because there is
one flow it does not act on.

**Capsules.** HTTP/2 has no datagrams, so the tunnel borrows the capsule protocol: the body is an
endless stream of `type · length · payload` records, and a record of type `0` carries one IP packet.
Both numbers are QUIC variable-length integers, so a small packet costs two bytes of framing. Nothing
in `src/transport/capsule.rs` knows about IP.

### Choosing

[`--transport`](../reference/cli.md#--transport-how) picks for the run: `auto` (the default), `h3`
or `h2`.

Under `auto` an attempt tries HTTP/3, and when it does not open — QUIC never answered, the endpoint
said nothing after the handshake, the request was refused, or the path cannot fit a packet — HTTP/2
is tried in the same attempt. HTTP/3 is then **parked**: the attempts after it go straight to HTTP/2
until the line changes, a reconnect is asked for, or ten minutes pass. A link that drops UDP to the
endpoint pays HTTP/3's timeouts once, not on every reconnect. Three HTTP/3 tunnels in a row dying
young having carried little park it the same way — see
[when a limit is being enforced](#when-a-limit-is-being-enforced).

The bounds on one HTTP/3 try are what keep the fallback inside the engine's 20-second attempt:

| Constant | Value | Why |
| -------- | ----- | --- |
| `HANDSHAKE_WAIT` | 4 s | The QUIC handshake, measured in tens of milliseconds. |
| `EXCHANGE_WAIT` | 4 s | SETTINGS and the CONNECT's answer together, measured at 135–208 ms. |
| `PATH_WAIT` | 2 s | Path MTU discovery making room for a full packet. |
| `PARK_FOR` | 10 min | How long HTTP/3 is left alone when nothing brings it back sooner. |

**A refusal over HTTP/3 never replaces the device.** A 4xx to the HTTP/2 request is read as the
endpoint declining this device (see [replacing a refused device](#replacing-a-refused-device)). Over
HTTP/3 the same status could be about the request — a header the endpoint stopped taking — and
reading it as the device would register a new one every ten minutes without fixing anything. So it is
reported as its own error, and under `auto` HTTP/2 is asked next: its answer speaks for the device.

The split handshake strategies cut TCP segments, so they always ride HTTP/2.

**A tunnel over HTTP/2 moves to HTTP/3 once it may.** Every 30 seconds (`UPGRADE_EVERY`) a tunnel
over HTTP/2 looks at whether an attempt made now would start with HTTP/3 — `auto`, a handshake QUIC
can carry, and HTTP/3 not parked. When it would, HTTP/3 is opened beside the tunnel while HTTP/2 keeps
carrying, and the pump hands over to it without a backoff and without a `connecting` phase. Nothing
the connections inside can see moves: the routes point at the adapter, and the endpoint gives the
device the same addresses over either carrier. A try that fails parks HTTP/3 again and says so at
`info`; the HTTP/2 tunnel never noticed.

## The queue

Everything the machine sends passes through `src/queue.rs` before it reaches the tunnel. **The
sending direction only** — packets arriving from the endpoint go straight to the adapter with
nothing in between.

That distinction is worth stating because it bounds what this can fix. Measured over twenty minutes
of video and browsing: 223.7 MiB in against 9.8 MiB out, and every counter here at zero with
`worst_wait` never reaching a millisecond. The queue engages when upload saturates, which a
download-shaped session never does.

It is `fq_codel`, in the two halves that matter:

**Flow queueing.** Packets are filed by 5-tuple into 64 buckets and the buckets are served by
deficit round-robin. A flow can only hold up itself. A bucket that was empty is served *before* the
ones already backlogged, so a page of small requests loads while something else is
downloading, because every new request is a new flow.

Never within a flow, though: each bucket is a FIFO. Reordering inside one connection is read as loss
by the TCP at both ends of it, so fairness is between flows and nowhere else.

**CoDel.** A packet that has been waiting longer than the target, for longer than the interval, is
told to slow down, and the rate of telling rises with the square root of how long the queue refuses
to drain. Doing that inside a tunnel that could simply buffer looks wrong until
[TCP-over-TCP](#http2) is read again: over HTTP/2 this IS the congestion signal, and without it the
inner connections have no reason to slow down. Over HTTP/3 the path's own losses do reach them, but
QUIC holds what its congestion window cannot send yet in a plain FIFO. That buffer is kept to 32 KiB,
so the backlog stays here, where it is served per flow and CoDel decides what it costs.

**How a sender is told is the sender's own choice.** One that set ECN's ECT bits has said it would
rather be marked than lose the packet, so the packet is delivered carrying the congestion mark —
nothing is retransmitted, and the IPv4 header checksum is put back. One that said nothing is told
the only other way there is, and what is dropped is retransmitted by the connection that sent it,
exactly as a drop on any other link would be.

**The interval is measured, not assumed.** It starts at CoDel's published 100 ms and then follows
the tunnel's own round trip, which the liveness check already has for nothing — QUIC's estimate over
HTTP/3, the ping's over HTTP/2. The tunnel leg
is only part of each inner connection's path, so the measurement is a floor: it is multiplied by
four, held between 50 and 300 ms, and smoothed over about a minute. An ordinary 25 ms leg reproduces
the 100 ms default exactly — the constant is derived rather than replaced. The target stays a
twentieth of it, which is CoDel's own ratio.

**Acknowledgements are thinned.** A later acknowledgement says everything an earlier one said, so
the earlier ones still waiting in a flow are removed — `sch_cake`'s ack filter, and its rules are
kept exactly. Only when the newer one acknowledges *strictly more*: a repeated one is a duplicate,
and duplicates are how a sender learns to retransmit before its timer fires. The most recent
redundant one stays, so at least two are always on their way. And only ones carrying no options at
all, which keeps selective acknowledgements and timestamps out of reach. Buckets are shared by
hashing, so the connection is compared and not assumed.

There is also a hard ceiling of 2 MiB, for a burst arriving faster than the tunnel could drain it
under any policy. Overflow is taken from the fattest bucket rather than from the arriving packet, so
a flood cannot push out the flows it is drowning.

**What waited out a gap is not sent on the next tunnel.** While there is no tunnel nothing drains the
queue, and CoDel cannot act — it decides as packets leave, and none leave. So when a tunnel comes up,
every packet that has waited a second or more is dropped first (`STALE_AFTER`, RFC 6298's initial
retransmission timeout): its sender has sent it again by then, and the old copy would spend the new
tunnel's first moments on a duplicate. Each bucket's standing-delay state is cleared with it, because
the delay was the gap, not the new tunnel.

The `queue` line in the journal is what says whether any of this is doing anything: how much is
waiting, in how many flows, the worst wait against the interval being worked to, how many senders
were marked and how many dropped, how many acknowledgements were thinned, and how many packets went
stale. Steadily zero marking *and* dropping under load is the suspicious reading, not a small
non-zero one.

Over HTTP/3 a `path` line follows it: QUIC's round trip and congestion window, how many of this
side's packets the path lost, and how many datagrams arrived against how many the tunnel read. A
download that loses packets is read off it — a gap between arrived and read is QUIC's receive buffer
on this machine overflowing, `lost` is the path, and a loss neither shows happened before QUIC.

**What is deliberately not done here: clamping MSS.** It is the standard move for a tunnel, and it
belongs to a router forwarding between links whose endpoints cannot see each other's MTU. This core
is not that — it *is* the link, and the stack on this machine derives its own announced MSS from the
adapter MTU while the far end derives its own from what we announced. There is nothing left over to
clamp. Raising the MTU is `--mtu`, and it is a measurement rather than a setting.

Packets leave in runs of up to 32. Over HTTP/2 a run is written as one capsule run — one frame,
one TLS record, one system call for what would otherwise be one of each apiece. Over HTTP/3 each
packet is its own datagram, and QUIC packs them into its packets.

## When a limit is being enforced

A tunnel can open, work, and be killed a few seconds later — measured on a filtered link, a flow
classified by its name is cut at 19.2 KiB carried. That looks exactly like a link going away, and
the difference matters: retrying is the answer to one and not to the other.

The engine records how long each tunnel lived and how much it carried, and counts the ones that died
inside a minute having carried under 256 KiB. One is not evidence. Three in a row is, because a
limit enforced on volume produces the same short life every time and nothing else does — at which
point a `notice` says so and names what to do about it.

When the run is of HTTP/3 tunnels, it also [parks](#choosing) HTTP/3: a limit enforced on the flow
would cut every HTTP/3 tunnel the same way, and HTTP/2 is there to carry meanwhile. An HTTP/3 tunnel
that took over from a working HTTP/2 one parks HTTP/3 on its first short life: the line was carrying
a moment before, so it is not what went away.

## Keeping it up

`engine::run` never returns. Every failure is a reason to open another tunnel, not a reason to stop;
stopping is the caller's decision, made by dropping the future.

### The failure that does not report itself

A link taken away does not close the connection. It leaves it hanging — neither closed nor carrying
anything — and nothing in the socket API says so. The only way to find it is to ask.

| Constant | Value | Why |
| -------- | ----- | --- |
| `PING_EVERY` | 5 s | How often the endpoint is asked whether it is still there. |
| `PING_TIMEOUT` | 5 s | How long an answer is waited for. |
| `CONNECT_TIMEOUT` | 20 s | One attempt at opening a tunnel, so a dead link cannot stall the schedule. |
| `SETTLING` | 300 ms | How long the line is given to settle after an interface change, before it is asked about. |
| `BACKOFF` | 1, 2, 4, 8, 15 s | Wait before each retry; the last entry repeats. |

Together the first two set the worst case for noticing a dead tunnel: **ten seconds**. Measured
against a link taken away on purpose, an earlier pair of fifteen and ten took twenty-four — a long
time to sit looking at a page that will not load.

Over HTTP/3 there is no ping to send, and none is needed. QUIC sends a keep-alive whenever the
connection has been quiet for two seconds, so a live connection always has something arriving from
the endpoint, and the check waits for anything at all to arrive after it asked. QUIC's own idle
timeout, ten seconds, ends a connection nothing is asking about.

Being this eager is safe because of the asymmetry: reconnecting costs a fraction of a second and
touches neither the adapter nor a single route, so a false alarm on a congested line is almost free,
while a real failure gone unnoticed costs the person everything they were doing.

The first backoff entry is short on purpose. A tunnel that was up a moment ago has usually lost
something momentary, and making the user wait out a long backoff for that is the common case being
punished for the rare one.

### Asking early

`src/link.rs` registers `NotifyIpInterfaceChange`. Windows calls back whenever an interface appears,
goes away or changes, and the callback does one thing: it says the line changed. The engine's
keepalive interval and its backoff wait both end early on that signal, after `SETTLING`. At `debug`
the journal names what woke them — the interface by the name Windows shows for it, and whether it
appeared, went away or changed — written where the engine acts on it, not on the callback's thread.

It is **not** a reconnect. Throwing away a working tunnel because some unrelated adapter appeared
would spend a handshake on nothing, and adapters appear for all sorts of reasons — a virtual switch,
a phone plugged in. Asking the question early is free when the answer is yes.

A line change unparks HTTP/3 only when the line actually moved: when the source address the route
to the HTTP/3 endpoint gives is no longer the one it was — the adapter went away, came back, or the
machine is on another network. A Wi-Fi adapter reports parameter changes every few seconds with the
path unchanged, and unparking on those would make parking last seconds on a link that drops QUIC.
The check each change asks for is still asked early either way.

**`NotifyRouteChange2` cannot be used here.** This core writes to the
routing table itself, several hundred rows at a time on bring-up and again on every policy edit —
every one of which would come back as a notification, and each notification would ask the tunnel to
check itself. The interface-level notification is not free of this either: the adapter this core
owns is an interface like any other. So the callback ignores anything about that adapter, by LUID,
and that filter is what the module's test pins.

### Phases

The engine publishes one of three phases on a `watch` channel, which is what
[`status`](../reference/control-pipe.md#status) reports:

| Phase | Carries |
| ----- | ------- |
| `connecting` | the attempt number, counting from one and reset whenever a tunnel comes up |
| `up` | the carrier, and the timings of each stage: TCP, TLS, HTTP/2 and CONNECT, or QUIC, SETTINGS and CONNECT |
| `lost` | why, and how long until the next attempt |

## IPv6, measured

Whether the tunnel carries IPv6 is asked, once per connect, and never assumed — see
[decisions](../design/decisions.md#4-dual-stack-with-no-opinion-about-which-family-wins). The probe
in `src/probe.rs` sends one DNS query over the live tunnel and waits for one answer: the smallest
exchange that proves a path, with no handshake state to keep.

Nothing about it is a test harness. The packet goes out over the real tunnel, and the UDP checksum in
it is the one the endpoint validates — over IPv6, unlike IPv4, a checksum is not optional, and a
datagram carrying a wrong one is discarded without comment.
