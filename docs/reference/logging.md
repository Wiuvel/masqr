# Logging

One line per thing that happened, on **standard output**, with the level word first:

```text
LEVEL  scope    message
```

```text
INFO   dns      A youtube.com → remote (rule 12) · 4 address(es), routed · 38 ms
NOTICE route    +4 -0, 482 prefixes now
NOTICE tunnel   ipv6 is carried
NOTICE tunnel   HTTP/3 did not open (…); carrying over HTTP/2. HTTP/3 is tried again when …
NOTICE warp     the endpoint refused this device (401); a new one is registered in …
DEBUG  stop     asking the reader to leave
```

Standard output, because the thing reading it is the application that started this process and that
is the channel it already has.

**No timestamps.** The reader stamps every line as it arrives, and two clocks on one line only ever
disagree.

Each line is written with a single `writeln!` under one lock. Two writes could interleave with
another thread's line and produce a line that belongs to neither.

## Levels

| Level | What belongs at it |
| ----- | ------------------ |
| `error` | Something failed and will not be retried into working. |
| `warn` | Something is wrong and the core is carrying on. |
| `notice` | A decision a person would want to know about without having asked. |
| `info` | One line per thing that happened. **The default.** |
| `debug` | The contents: which addresses, which prefixes, which packet. |

A level enables itself and everything more severe. `--log-level` sets it at start; the
[`log` command](control-pipe.md#log) changes it on a live tunnel, and the change is announced only
when it actually moved.

## Why `debug!` stays on the packet path

The level is **one atomic integer, read before a message is built**. A line that will not be printed
costs a load and a comparison — nothing is formatted, nothing is allocated. That is what makes it
reasonable to leave a `debug!` on the packet path rather than deleting it once it has served its
purpose.

`traffic` and `queue` are the ones that would otherwise be noisy: they report on a timer, and they
sit at `debug` for exactly this reason.

`queue` is the line to read when the tunnel is carrying plenty and something still feels slow,
because it answers the question `traffic` cannot — not how much went through, but how long it waited
to. It reads:

```
queue  14 pkt / 17.8 KiB in 3 flow(s) · worst wait 8 ms of 100 ms
          told to slow down: 21 marked, 4 dropped · 0 over limit · 96 acks thinned · 0 stale
```

`worst wait ... of ...` is the longest a packet waited against the interval CoDel is currently
working to, which follows the measured round trip. `marked` and `dropped` are the same signal sent
two ways — neither is a fault, they are how the connections inside the tunnel are told to slow down,
which over HTTP/2 the outer TCP would otherwise hide from them. `over limit` is different: that is the hard
ceiling, and a non-zero one means the tunnel could not keep up at all.

Steadily zero marking *and* dropping under load is the reading worth investigating, because it means
the queue is not the thing shaping the traffic. `stale` counts packets dropped as a tunnel came up,
having waited for one longer than their senders wait before sending again.

Over HTTP/3 a third line, `path`, reports what QUIC knows about the connection:

```
path   rtt 36 ms · cwnd 1.4 MiB · 12 of 48210 pkt lost · 39104 datagram(s) in, 39104 read
```

The last two numbers are counted from when the tunnel came up. Datagrams that arrived and were never
read were dropped by QUIC's receive buffer on this machine; `lost` is this side's packets the path
lost. It is written only while an HTTP/3 tunnel is up, and once more with the session total when the
core stops.

## Scopes

The second column names the part that spoke. Not an enumeration — new ones appear with new code —
but the common ones:

| Scope | About |
| ----- | ----- |
| `warp` | Registration and the device. |
| `tunnel` | The transport: connecting, lost, reconnected, which carrier, IPv6 measured. |
| `adapter` | The Wintun device and its addresses. |
| `route` | Prefixes going in and out of the routing table. |
| `dns` | Queries, which resolver answered, and whether the answer was routed. |
| `names` | The name policy rule and the takeover. |
| `link` | Windows saying an interface changed. |
| `log` | The level itself changing. |
| `stop` | Each step of the shutdown, so a failed one names the call it did not get past. |
| `traffic` | The counters, on a timer. |
| `queue` | What is waiting in front of the tunnel, and what was dropped, on the same timer. |
| `path` | QUIC's view of an HTTP/3 tunnel's path, on the same timer. |

## Why the level word comes first

It is spelled the way the application's existing classifier expects, so a line from this core is
coloured by the same rule as any other line in the same journal. A journal where severity is guessed
differently per source is one nobody trusts.

## Panics

A panic hook prints

```text
ERROR  panic    <message> — at <file>:<line>
```

and chains onto whatever hook was installed before it, so the default output is not lost.

This does **not** cover an access violation. `0xC0000005` is Windows taking the process down; no
hook runs, and the only evidence is the exit status. Anything supervising the core should decode
one — a status code in the billions is not an exit code, it is a crash. See
[the shutdown contract](../architecture/adapter.md#the-shutdown-contract) for the one that used to
happen and how it was fixed.
