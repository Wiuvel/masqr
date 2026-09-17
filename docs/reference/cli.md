# Command line

```text
masqr [version|register|probe|up|names|handshake] [options]

  --identity   <path>    where the registered device is kept (default: identity.json)
  --wintun     <path>    which wintun.dll to load (default: beside this binary)
  --target     <prefix>  route this prefix into the tunnel; may be repeated
  --dns-listen <addr>    answer DNS here, once a policy is installed over the pipe
  --log-level  <level>   error | warn | notice | info | debug (default: info)
  --handshake  <mode>    named | no-sni | split | split-slow | fronted (default: fronted)
  --sni        <name>    the name `fronted` presents               (default: www.cloudflare.com)
  --transport  <how>     auto | h3 | h2                            (default: auto)
  --mtu        <bytes>   the adapter's MTU, 1280..=9000            (default: 1280)
```

Options are named rather than positional, because this is the line an application writes: a position
is easy to get subtly wrong and impossible to read back in a log.

**Every command sweeps first.** Before anything that needs a name resolved, and on every command
rather than only the one that answers names, the core removes any
[name policy rule](../architecture/names.md) left behind by an earlier run. A rule left by a core
that was killed points the machine at a resolver that is not running — so until the sweep has run,
there is no name resolution on the machine at all, including the resolution the enrolment itself
needs.

Exit codes: `0` success, `1` the command failed (the failure and its whole cause chain are printed),
`2` the command line could not be parsed.

## `masqr version`

Prints `masqr version <x.y.z>` and exits. Nothing else runs — this is what a build script and an
inventory read.

## `masqr register`

Registers a device, or reports the one already registered, and writes
[`identity.json`](identity.md). Registering creates a real device on Cloudflare's side, so this is
done once; later runs reuse the file.

Needs the endpoint to be reachable. It is the only part of the core that resolves a name.

## `masqr probe`

Opens the tunnel and resolves a name through it. A DNS query is the smallest exchange that proves
the whole path — one datagram out, one back, with no handshake state to keep. An answer carrying
addresses means the identity was accepted, the endpoint agreed to CONNECT-IP, the framing is right,
and Cloudflare routes packets for the address it assigned. The `tunnel` line names the carrier it
came up on; `--transport h3` or `--transport h2` checks one of them alone.

Does not create an adapter, so it does not need to be elevated.

## `masqr up`

Brings the adapter up and carries packets until stopped. This is the command an application starts.

**Must run elevated** — creating a network adapter does.

`--target` may be repeated and is there for convenience while working on the core by hand; the
routed set is meant to be driven over the [control pipe](control-pipe.md), which can change it on a
live tunnel.

`--dns-listen` starts the resolver on that address. Without it the core carries only what
`--target` and the pipe name, and `names claim` is refused — a core that is not answering DNS cannot
be the machine's resolver.

Stops on `{"command":"stop"}` over the pipe, or on a console interrupt.

## `masqr names`

Leaves the machine resolving names the way it did before this core ever ran, and exits.

The sweep every command performs is all this one does, so that whatever supervises the
core can put the machine back **without knowing where any of this is kept**. That is the recovery
path after a core was killed rather than stopped.

## `masqr handshake`

Opens the tunnel once per ClientHello strategy and carrier, and reports which of them this link let
through.

It answers one question: **can this core carry its own handshake, or does a DPI bypass have to be
running underneath it?** On a filtered link the tunnel's TLS handshake is cut with no reply — what is
matched is the name in the clear, not the address and not the fingerprint. That is why the
application pins the endpoint's addresses and `*.cloudflareclient.com` in its bypass lists.

Each strategy is taken all the way to CONNECT-IP, because a handshake that survives is not yet a
tunnel that carries: the endpoint can answer and still refuse to carry packets for this identity.

Run it on the link that has the problem, **with the bypass off**. On a link that does not filter the
name every strategy opens, and the run proves nothing.

| Strategy | What goes on the wire |
| --- | --- |
| `named` | the name the endpoint is registered under, in one write — the control that tells a link filtering the name from one that is not |
| `no-sni` | no `server_name` extension at all (a literal address may not be sent as SNI, so none is) |
| `split` | the name, cut across a TCP segment boundary **inside the name** |
| `split-slow` | the same cut, with the second half held back past a reassembly window |
| `fronted` | an unfiltered Cloudflare name in place of the registered one, and **what a run defaults to** |

Each strategy that names something — `named`, `no-sni`, `fronted` — is tried over HTTP/3 as well as
HTTP/2: the name travels in QUIC's Initial as it does in TLS's ClientHello, and a link can treat the
two paths differently. The splits cut TCP segments and are tried over HTTP/2 only. The verdict about
the name is read off HTTP/2, where every strategy ran; a line after it says what held over HTTP/3.

**The endpoint does not route by the name.** Measured end to end: `no-sni` and `fronted` both
complete CONNECT-IP with the key pinned at registration verifying, which is only possible against
the real endpoint. So the name costs nothing on the far side and is free to change — the whole
reason the other four strategies can exist at all.

**Why `fronted` is the default.** The endpoint does not read SNI, so on a link that ignores the name
it costs nothing; on a link that reads it, it is the difference between a tunnel and 19.2 KiB.
Measured in the field with no bypass underneath: 223.7 MiB carried, no tunnel lost. `named` is what
to reach for if the endpoint ever starts requiring its own name.

The verdict line reads the results together, and separates two questions that a single run answers
unequally. Whether **the endpoint** accepts a strategy travels with the strategy and is settled
anywhere. Whether **the link** lets it through is a property of where the run happened: if `named`
opens, the link was not filtering the name and has said nothing about one that does.

`fronted` carrying while nothing else does means the link classifies the flow by the name and then
acts on what it named. Omitting the name is not a way out of that — an unclassifiable flow is
treated the same, which is measured, not assumed. What works is a name the link does not act on.
Nothing opening at all, `fronted` included, means the address is blocked and none of this is the
remedy.

Two things the run cannot see for itself. It prints `leaving by <address>` from a plain connection
before trying anything, so a full-tunnel client holding the default route is visible — but a
**packet-level DPI bypass fronts the handshake from that same address** and does not show at all.
Stop it before trusting the table.

## Options

### `--identity <path>`

Where the registered device is kept. Default `identity.json` in the working directory. It is a real
credential for a real device — see [identity](identity.md).

### `--wintun <path>`

Which `wintun.dll` to load. Default: beside the binary. The DLL is loaded at run time rather than
linked, so a missing one is a message and not a process that will not start.

### `--target <prefix>`

A prefix to route into the tunnel: `address` or `address/length`, either family. May be repeated.

### `--dns-listen <addr>`

Where the resolver listens, as `address:port`. Loopback is the sensible choice — nothing outside the
machine should be able to reach it. The resolver answers nothing until a
[policy](control-pipe.md#dns) is installed.

### `--log-level <level>`

`error`, `warn`, `notice`, `info` or `debug`. Default `info`. Can be changed on a live tunnel over
the pipe. See [logging](logging.md).

### `--handshake <mode>`

Which ClientHello the tunnel's own TLS session presents. Default `fronted`: an
unfiltered Cloudflare name in place of the registered one, which the endpoint ignores and a filtering
link does not act on. `named` restores the connection the stock client makes. Run `handshake` to see
what a particular link lets carry; `handshake --handshake <mode>` tries that strategy alone.

### `--sni <name>`

The name `fronted` presents instead of `www.cloudflare.com`. It exists to be
measured: a link that stops leaving the default name alone needs another name already known to
carry, and `handshake --handshake fronted --sni <name>` is how one is found — the endpoint does not
read SNI, so what decides is only whether the link acts on the name.

Both `--handshake` and `--sni` set the initial state. The `--sni` value can be updated on a live tunnel over
the control pipe (hot-reloading) without restarting the core.

Must be a DNS name; an address is refused, since `no-sni` is the strategy for sending none. Refused
beside any handshake other than `fronted`, where it would change nothing.

### `--transport <how>`

Which carrier the tunnel rides, for the whole run. Default `auto`: HTTP/3, and HTTP/2 in the same
attempt when HTTP/3 does not open, with HTTP/3 then left alone until the line changes, a reconnect is
asked for, or ten minutes pass. `h3` and `h2` take one carrier and report its failures rather than
covering them — `h3` for checking HTTP/3 on a link, `h2` for the carrier this core ran on before
HTTP/3. See [the tunnel](../architecture/tunnel.md#two-carriers).

`--transport h3` beside a split handshake is refused: a split cuts TCP segments, and there are none.

### `--mtu <bytes>`

The adapter's MTU, 1280 to 9000. Default 1280 — what WARP itself hands out.

It exists to be measured, not tuned. Over HTTP/2 nothing fragments: the outer TCP segments whatever
it is given, so a larger MTU buys fewer capsules for the same bytes. Over HTTP/3 each packet has to
fit one QUIC datagram, so a larger MTU needs a path that fits it — or HTTP/3 is unfit for the run,
and HTTP/2 carries. What it costs is unknown until a run says whether the endpoint carries it. Raise
it, send traffic, and see.

Refused outside that range: below 1280 the adapter is not a link every IPv6 host is required to be
able to use, whatever the tunnel would accept.
