# Documentation

Notes on how the core is built and why. Start with the
[architecture overview](architecture/overview.md) — everything else assumes it.

## Categories

### Architecture

- [Overview](architecture/overview.md) — the one idea the design follows, the module map, the
  threads, and what happens between start and stop.
- [The tunnel](architecture/tunnel.md) — registering a device, the TLS session, `CONNECT-IP` over
  HTTP/3 or HTTP/2 and how one is chosen, the framing of each, and the loop that keeps it alive.
- [The adapter](architecture/adapter.md) — Wintun, the addresses on it, the routes into it,
  ownership, and the shutdown order that is load-bearing.
- [DNS](architecture/dns.md) — the forwarder, the policy that decides each query, leases, and how
  the program that asked is known.
- [The machine's names](architecture/names.md) — taking name resolution over, proving it happened,
  and giving it back.

### Reference

- [Command line](reference/cli.md) — the five commands and their options.
- [Control pipe](reference/control-pipe.md) — every request and reply, with examples.
- [Identity file](reference/identity.md) — the one thing this core persists.
- [Logging](reference/logging.md) — the line format, the levels, and what is said at each.

### Guides

- [Building](guide/building.md) — the toolchain and what it verifies.
- [Running](guide/running.md) — what the core needs to start, and what it changes on the machine.
- [Testing](guide/testing.md) — `cargo test` and what each module proves.

### Design

- [Decisions](design/decisions.md) — the four that shape everything else, and the alternative each
  one closed off.
- [Limits](design/limits.md) — what this core does not do, and why each is a decision rather than a
  gap.

## Conventions

- **The source is the other half of this.** Every module starts with why it exists and what it
  leaves out; `cargo doc --no-deps --open` renders it. These documents describe how the parts
  fit together — they do not restate what a module already says about itself.
- **Links to code** name a file, and a symbol where it helps (`src/dns/policy.rs`,
  `Policy::decide`), never a line number — so they survive edits.
- **Documents describe the code as it is**, not its history and not what is planned.
