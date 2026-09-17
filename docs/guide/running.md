# Running

## What it needs

| | |
| --- | --- |
| **Windows** | The core is Windows-only: Wintun, IP Helper, the name resolution policy and named pipes are all Windows. |
| **Elevation** | `up` only. Creating a network adapter and writing routes require it. `version`, `register` and `probe` do not. |
| **`wintun.dll`** | Beside the binary, or named by `--wintun`. Loaded at run time. |
| **A reachable endpoint** | Registration talks to Cloudflare over HTTPS **by name**, and that leg still depends on the name resolving and getting through. The tunnel itself does not: it dials a literal address and by default presents a name the link does not act on (see [`--handshake`](../reference/cli.md#--handshake-mode)), over HTTP/3 or, where that does not open, HTTP/2. A handshake cut with no reply is reported as exactly that rather than as an unexplained end of file. |

## A first run

```powershell
masqr register                      # once per machine: writes identity.json
masqr probe                         # opens the tunnel, resolves one name through it
```

`probe` is the readiness check. A DNS query is the smallest exchange that proves the whole path, so
an answer means the identity was accepted, the endpoint agreed to CONNECT-IP, the framing is right,
and Cloudflare routes packets for the address it assigned.

## Carrying traffic

```powershell
masqr up --identity C:\path\identity.json `
         --wintun C:\path\wintun.dll `
         --dns-listen 127.0.0.1:53 `
         --target 1.1.1.1/32
```

Elevated. From here the [control pipe](../reference/control-pipe.md) is how it is driven: the routed
set and the name policy are replaced on a live tunnel, so nothing here needs restarting to change
what it carries.

## What it changes on the machine

Three things, and only three:

| Change | Removed by |
| ------ | ---------- |
| A Wintun adapter with the two assigned addresses on it | The process ending — Windows removes it, and the routes go with it. |
| Host routes into that adapter | The adapter going. |
| One name resolution policy rule, if `names claim` was used | The core stopping, or the next run's sweep, or `masqr names`. |

**Only the third can outlive the process.** That is why every command sweeps for one before doing
anything else, and why [`masqr names`](../reference/cli.md#masqr-names) exists: a supervisor can put
the machine back without knowing where any of this is kept.

Nothing is written to any adapter's DNS settings — see
[the machine's names](../architecture/names.md#not-by-writing-to-an-adapter).

## Stopping it

`{"command":"stop"}` over the pipe, or a console interrupt. **Asked rather than killed**: the core
takes its adapter and every route with it when it stops on request, and a kill leaves that to the
driver to notice.

## Supervising it

For anything starting the core as a child process:

- **Kill an orphan before spawning.** A live orphan owns the adapter whose name the new start asks
  Windows for, and Windows refuses a held name — the bring-up fails with "already exists" and keeps
  failing while the orphan runs. Waiting cannot help; nothing is on its way out.
- **Wait for the core to say it is up**, by polling [`status`](../reference/control-pipe.md#status),
  rather than for a line in the journal. A TUN that is up does not mean the tunnel carries traffic.
- **Give the names back before the core goes**, through the core while it is still running. For as
  long as the machine's names point at a resolver that has stopped answering, it has no DNS at all.
- **Decode the exit status.** A status code in the billions is not an exit code, it is Windows taking
  the process down: `0xC0000005` an access violation, `0xC0000409` a failed internal check,
  `0xC0000374` heap corruption. A core that ended on its own says why in its own journal and exits
  with something small.
- **Run `masqr names` after a kill.** It is the whole recovery path.

## Reading what it says

One line per thing that happened, on standard output, level word first. See
[logging](../reference/logging.md). At `debug` the core names every DNS exchange — the question, the
resolver that answered, the addresses, and whether they were routed — which is the level to be on
when a page will not open and it is not clear whether the name or the route is at fault.
