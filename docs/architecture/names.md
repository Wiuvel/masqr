# The machine's names

Answering names is half of what makes routing follow them. The other half is making the machine
**ask** this resolver.

Code: `src/names.rs`.

## Why it has to be every name

A core that answers names is not doing it for privacy: its answer is what creates the route. An
address it never handed out is an address it never routed, so a query answered by anything else is a
connection that quietly leaves over the line instead of the tunnel.

Every name has to arrive here. "Most of them" is not a state this can be left in.

## Not by writing to an adapter

Writing the resolver onto the machine's adapters is the wrong mechanism. It
overwrites a setting the person who owns the machine chose, which then has to be recorded somewhere,
put back correctly, and put back **at all** — and a machine whose adapters point at a resolver that
stopped existing has no name resolution until something notices.

The record is the fragile part, and the fix is not to keep a better record. It is to have nothing to
record.

## One name resolution policy rule

Instead the core writes a single rule under

```text
HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{6D617371-…}
```

| Value | Type | Contents |
| ----- | ---- | -------- |
| `Version` | `REG_DWORD` | `2` — the rule format |
| `Name` | `REG_MULTI_SZ` | `.` — the namespace meaning every name |
| `GenericDNSServers` | `REG_SZ` | the address the core answers on |
| `ConfigOptions` | `REG_DWORD` | `0x8` — the rule names ordinary DNS servers |
| `Comment`, `DisplayName` | `REG_SZ` | `masqr` — the mark |

The rule sits **above** the choice of which adapter's servers to ask, so it does not depend on
interface metrics, on which adapter holds the default route, or on whether Windows decides to ask
several adapters at once. No adapter is touched. Undoing it is deleting a rule of this core's own,
which needs no memory of what was there before.

The GUID is **fixed rather than fresh per run**, so a core that was killed leaves exactly one rule
behind however many times it happens, and the next one replaces it rather than adding to it. A pile
of rules is not merely untidy — the policy is consulted on every query.

### Why not a route

This core already owns an adapter and installs routes into it, and Windows removes both when the
process ends — so routing the machine's resolver into the tunnel and answering it there would need
no cleanup at all.

It is not done because the machine's resolver is very often its **default gateway**. A host route for
that address would take the gateway away from the adapter that reaches it, and the link itself would
stop working. A mechanism that is safe only when the resolver happens to be a public address is not
one a core can offer.

## The claim is proved, not assumed

Writing a rule and reporting success is not the same as the machine using it. A takeover reported
without having happened is **the one failure with no symptom of its own**: names keep resolving,
from somewhere else, and every address they return is one the tunnel never hears about.

So `take_over`:

1. writes the rule;
2. invents a name in a namespace nothing answers — `<random>.masqr-check.invalid`, different every
   time, because a name asked twice may be answered from a cache the second time and that would
   prove the opposite of what is being measured;
3. asks **the operating system** to resolve it, through `getaddrinfo` on a blocking task. Asking this
   resolver's socket directly would prove only that the socket is open; what is being measured is the
   path an ordinary program's name takes;
4. waits up to `CARRIED_WITHIN` (3 s) for that query to arrive at its own listener;
5. and if it did not, **removes the rule and reports failure** — so a caller that falls back to
   something else is not falling back onto a rule still in place.

## Forgetting what the machine already knows

A rule about a name that was resolved a minute ago decides nothing. The answer sits in the machine's
resolver cache; the program holding it never asks again; and the address it goes on using is one this
core never handed out and therefore never routed. The rule looks installed — it *is* installed — and
it does nothing at all until its predecessor's TTL runs out, which is minutes and is
indistinguishable from a rule that was never installed.

So every change to what the answers would be takes the old ones with it. `forget_answers()` calls
`DnsFlushResolverCache` — resolved from `dnsapi.dll` at run time, because there is no linkable
header for it — on:

- the policy being replaced ([`dns`](../reference/control-pipe.md#dns)),
- the names being taken over, and
- the names being given back.

This is what "a domain I just added does not work until I restart protection" looks like when the
flush is missing.

## Giving them back, and repairing after a kill

`release()` sweeps the policy key and deletes every rule whose `Comment` is `masqr`, returning how
many there were. Everything the sweep needs is carried **on the rule itself** rather than in a record
kept alongside, so a run can repair what an earlier one left with nothing having
survived in between, and what keeps it from removing a rule belonging to somebody else.

It is safe to call having written none, which is why every command runs it before doing anything
else, and why [`masqr names`](../reference/cli.md#masqr-names) — which does nothing but sweep and
exit — is a complete recovery path for a supervisor.

## Where the core listens

Whatever `--dns-listen` names; the application that ships this uses `127.0.0.1:53`. Loopback, so
nothing outside the machine can reach it, and a fixed port because that is the only one the
operating system can be pointed at.

A `names` claim is refused outright when the core is not answering DNS at all: a core that is not a
resolver cannot be the machine's resolver, and pretending otherwise would leave it pointed at a
closed socket.
