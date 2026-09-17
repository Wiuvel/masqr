# Control pipe

`\\.\pipe\masqr` — one JSON object per line in each direction.

## Why a pipe

The core is elevated; a port on localhost is not. Anything running as the user could connect to a
localhost port, which would mean inventing a secret to hand it and a place to keep the secret.

A pipe carries its own access list, so the question is answered by Windows before a single byte is
read. The descriptor is

```text
D:P(A;;GA;;;BA)(A;;GA;;;SY)
```

— the built-in Administrators group and the system, and nobody else. `P` makes it protected, so
nothing is inherited into it; without that a permissive default on the pipe namespace would be
*added* to what is written here rather than replacing it. There is no secret to leak.

The first instance is created with `first_pipe_instance`, so a second core refuses to
start rather than quietly share the name with the one already running. The next instance is created
before the current one is handled, so a caller connecting while another is being answered is never
turned away.

Line-delimited because a request is small and a reply is small — and because it makes the interface
the interface drivable by hand while working on it.

## Replies

Every reply carries `ok`. A refusal is

```json
{"ok": false, "error": "<what was wrong>"}
```

and a refusal means nothing changed. Anything unparseable is refused the same way; a caller that
hangs up mid-sentence is ordinary and is not reported.

## `status`

```json
{"command": "status"}
```

Everything the application shows about the tunnel.

```json
{
  "ok": true,
  "tunnel": {
    "state": "up", "transport": "h3", "stages": { "quic_ms": 61, "settings_ms": 1, "connect_ms": 74 },
    "path": { "rtt_ms": 36, "cwnd": 1468000, "sent": 48210, "lost": 12, "datagrams": 39104, "read": 39104 }
  },
  "routes": ["1.1.1.1/32", "104.16.0.0/13"],
  "traffic": { "out": {"packets": 1204, "bytes": 183422}, "back": {"packets": 1180, "bytes": 942011} },
  "level": "info",
  "ipv6": "carried",
  "dns": { "queries": 812, "answered": 809, "failed": 3, "routed": 274, "leases": 96 }
}
```

`tunnel.state` is `connecting`, `up` or `lost`, and carries what belongs to that state:

| State | Extra fields |
| ----- | ------------ |
| `connecting` | `attempt` — counts from one, resets whenever a tunnel comes up |
| `up` | `transport` — `h3` or `h2`; `stages` — milliseconds per stage: `quic_ms`, `settings_ms` and `connect_ms` over HTTP/3, `tcp_ms`, `tls_ms`, `http2_ms` and `connect_ms` over HTTP/2; over HTTP/3, once the first liveness check has answered, `path` — QUIC's round trip and congestion window in bytes, packets sent and lost on the path, and datagrams arrived against packets read, both counted from when the tunnel came up (see [logging](logging.md)) |
| `lost` | `reason`, `retry_in_ms` until the next attempt, and `blocked` |

`blocked` on a lost tunnel means the handshake was refused on the way — over HTTP/2 the TLS
handshake cut with no reply, over HTTP/3 the QUIC handshake completed and then nothing answered —
rather than anything here being wrong. It is a separate field rather than a phrase in
`reason` because a supervisor has to act on it differently: retrying is not what fixes it, and the
sentence is not a contract.

`ipv6` is `carried`, `not carried` or `not measured yet` — three states rather than two, because
"not asked yet" is a reason to ask and "asked, and it does not" is an answer to keep.

`dns.leases` counts addresses held *because a name resolved to them*, as distinct from the prefixes
the application asked for — a level, which falls as leases expire.

`dns.routed` is the running total of prefixes those answers actually put into the routing table. Not
the addresses the answers held: an answer repeats addresses that are already routed, and a v6
address is left out entirely unless the tunnel was measured carrying v6. So `routed` climbing while
`leases` stands still means names are resolving to addresses that were already there, and `routed`
standing still on a busy resolver means the answers are not producing routes — the two together say
more than either alone.

## `routes`

```json
{"command": "routes", "set": ["1.1.1.1/32", "2606:4700::/32"], "ipv6": true}
```

Makes the routed set **exactly** this. Not a delta — the caller sends the whole set and the core
works out what moved, so the operation is idempotent and a lost reply harmless.

A prefix is `address` or `address/length`, either family. Whatever the set contains, a v6 prefix is
installed only when `ipv6` is true **and** the tunnel has been measured carrying IPv6; see
[decisions](../design/decisions.md#4-dual-stack-with-no-opinion-about-which-family-wins).

The lease half of the routed set is not affected: what DNS has learned is added to whatever is sent
here.

```json
{"ok": true, "added": ["2606:4700::/32"], "removed": []}
```

## `dns`

```json
{
  "command": "dns",
  "resolvers": [
    {"id": "remote", "kind": "doh", "address": "1.1.1.1", "url": "https://1.1.1.1/dns-query", "via": "tunnel"},
    {"id": "home", "kind": "plain", "address": "192.168.1.1", "via": "direct"}
  ],
  "rules": [
    {"match": {"suffix": "youtube.com"}, "resolver": "remote", "route": true},
    {"match": "any", "resolver": "remote", "route": true, "programs": ["discord.exe"]},
    {"match": "any", "resolver": "home"}
  ]
}
```

Replaces the policy **whole**. Never merged, so the core is never holding half of an old one.

**Resolver fields**

| Field | Meaning |
| ----- | ------- |
| `id` | what rules refer to it by |
| `kind` | `doh` or `plain` |
| `address` | always an address, never a name — a resolver that had to be resolved first cannot answer the first question of a session |
| `url` | required for `doh`; the name in it is what the certificate is checked against |
| `via` | `tunnel` or `direct` — whether the resolver's own address is routed into the tunnel |

**Rule fields**

| Field | Meaning |
| ----- | ------- |
| `match` | `{"exact": "…"}`, `{"suffix": "…"}` or `"any"`. Matching is by label: a suffix rule for `example.com` covers `a.example.com` and not `notexample.com` |
| `resolver` | the `id` of a declared resolver |
| `route` | whether the addresses in the answer become routes. Default `false` |
| `programs` | file names or full paths. Empty means every program |

**First match wins**, and the order is the caller's. A policy is validated at install, not on the
first query it decides — the previous one is still in place, and a machine answering names by
yesterday's rules is a working machine. Refused for: a rule naming an undeclared resolver, a resolver
declared twice, a rule matching an empty name, a `doh` resolver with no `url`.

Installing a policy **flushes the machine's DNS cache**. A rule about a name resolved a minute ago
decides nothing until the cached answer expires, which is indistinguishable from a rule that was
never installed.

```json
{"ok": true, "rules": 42, "resolvers": 4, "tunnelled": 1}
```

## `names`

```json
{"command": "names", "claim": true}
```

Takes the machine's names over, or gives them back.

Taking them over is **proved rather than assumed**: the core writes its rule, asks the operating
system to resolve a name it invented, and waits up to three seconds for that query to arrive at its
own listener. A claim that could not be proved is undone before the reply is written, so `ok: false`
means the machine is exactly as it was.

Refused when the core is not answering DNS at all.

```json
{"ok": true, "claimed": true}
{"ok": true, "claimed": false, "removed": 1}
```

## `log`

```json
{"command": "log", "level": "debug"}
```

`error`, `warn`, `notice`, `info` or `debug`. Takes effect on the next line. Announced in the journal
only when it actually moved — an application that sends the level alongside every policy edit would
otherwise fill the journal with reports of being told what it was already doing.

```json
{"ok": true, "level": "debug"}
```

## `reconnect`

```json
{"command": "reconnect"}
```

Throws the current tunnel away and opens a fresh one. **Routing does not move** — neither the
adapter, nor its address, nor a single route.

## `stop`

```json
{"command": "stop"}
```

Puts the adapter away and exits. The reply is written before the shutdown completes.

Asked rather than killed: the core takes its adapter and every route it installed with it when it
stops on request, and killing it leaves that to the driver to notice.

## Driving it by hand

```powershell
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'masqr', 'InOut')
$pipe.Connect(3000)
$writer = New-Object System.IO.StreamWriter($pipe); $writer.AutoFlush = $true
$writer.WriteLine('{"command":"status"}')
(New-Object System.IO.StreamReader($pipe)).ReadLine()
$pipe.Dispose()
```

The PowerShell session has to be elevated, for the same reason the pipe's access list exists.
