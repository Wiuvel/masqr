# Architecture overview

`masqr` is a MASQUE/WARP tunnel core for Windows. One protocol — MASQUE, over HTTP/3 or HTTP/2 —
one platform, one adapter, and a routing policy shaped by what is actually asked for. It is driven over a named pipe rather than a
configuration file, so what it carries changes on a live tunnel with nothing to restart.

## The one idea

**An answer is a route.**

A routing table decides by destination and by nothing else. So following a *name* means being the
thing that answered it. The resolver here hands out an address and, in the same moment, points that
address at the adapter. Nothing has to have been resolved in advance, and a content network handing
the browser an address nobody listed is no longer a target that quietly leaves over the line.

Everything else in the design is a consequence:

- **The adapter carries only what is tunnelled.** Direct traffic never enters it, so there is no
  second network stack on this side and nothing to send back out. No default route is installed.
- **Routes point at the *adapter*, not at the connection.** Replacing a tunnel moves neither the
  adapter, nor its address, nor a single route — so a reconnect costs a fraction of a second, which
  is what makes finding a dead tunnel eagerly a safe thing to do.
- **A program can be pulled into the tunnel, but not kept out of it.** A rule can say *when this
  program asks, the answer becomes routing*. The opposite cannot be built this way, because by the
  time the route exists it belongs to an address, not to a process.

## The pieces

```text
           Windows                                        Cloudflare
              │                                                │
  names       │  packets                                       │
     ┌────────┴────────┐                                       │
     ▼                 ▼                                       │
  [dns] ──leases──► [core] ◄──routes── [tun]                   │
     │                 ▲                                       │
     │              [engine] ──► [transport] ──CONNECT-IP──────┘
     │                 ▲
     └── [control] ────┘   policy, routed set, log level, stop
```

| Module | What it owns |
| ------ | ------------ |
| `tun` | The Wintun adapter, its addresses, and the routes into it. Owned: Windows removes the adapter when this process ends, and the routes go with it. |
| `core` | What is routed right now, the counters, the phase, and the one lock that keeps the two halves of the routed set from disagreeing. |
| `dns` | The resolver the machine talks to: which upstream answers a name, and whether the answer becomes routing. |
| `names` | What makes the machine ask this resolver at all — one name resolution policy rule, proved. |
| `transport` | The MASQUE leg: CONNECT-IP over HTTP/3, each packet a QUIC datagram, or over HTTP/2, packets in a capsule stream — TLS from the enrolled identity under both, and the choice between them. |
| `engine` | Keeping a tunnel up and moving packets across it, including the failure that never reports itself. |
| `warp` | The device: registering one, keeping it, and replacing one the endpoint refuses. |
| `control` | The named pipe everything above is driven through. |
| `link` | Windows saying an interface changed, so the tunnel is checked then rather than at the end of the next interval. |
| `probe` | Measurements that must not be assumed — chiefly whether the tunnel really carries IPv6. |
| `log` | One line per thing that happened, at a level that changes on a live tunnel. |

## Shared state

Three things outlive any one tunnel and are read by more than one task, so they live together in
`core::Core` rather than each task keeping its own answer:

- **The routed set.** Two halves — what the application asked for, and what DNS has learned — held
  under one lock, so two callers changing different halves end with the table agreeing with both
  rather than with a mixture. A v6 prefix is installed only when the application asked for IPv6
  *and* the tunnel was measured carrying it.
- **The phase.** `connecting` (with an attempt number), `up` (with the carrier and the timings of
  each stage), or `lost` (with a reason and how long until the next attempt). A `watch` channel, so the
  control interface reads the current value without waiting and the engine never blocks publishing
  one.
- **The counters.** Packets and bytes each way.

## Threads and tasks

Tokio's multi-threaded runtime, plus two OS threads that cannot be async:

- **The adapter reader.** `WintunReceivePacket` blocks; it waits on the adapter's read event *and*
  a quit event, so the thread can be asked to leave without anything being closed underneath it.
- **The interface-change callback.** Windows calls it on a thread of its own. It does one thing —
  says the line changed — and returns.

Everything else is a task: the packet pump in each direction, the DNS listeners (UDP and TCP), the
control pipe's accept loop and one task per connection, and the engine's supervision loop.

## From start to stop

`masqr up`:

1. Sweep any name policy rule a killed run left behind (by its mark), so nothing from before is
   still in force.
2. Load the identity, or register a device if this machine has none.
3. Create the adapter, put both assigned addresses on it, set the MTU.
4. Start the reader thread and the engine. The engine opens a tunnel; when it does, the phase
   becomes `up`.
5. Start the control pipe and, if `--dns-listen` was given, the resolver.
6. Serve until `stop` arrives over the pipe or the console is interrupted.

Shutdown order is not incidental — see [the adapter](adapter.md#the-shutdown-contract):

```text
stop watching the line  →  ask the reader to leave  →  wait for it  →  end the session  →  close the adapter
```

The routes go with the adapter, and the adapter goes with the process. What does *not* go with the
process is the name policy rule, which is why every command sweeps for one before it starts.
