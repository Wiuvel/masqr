# The adapter

The side of the tunnel the operating system sees: a Wintun adapter, the addresses on it, and the
routes into it.

Code: `src/tun/mod.rs`, `src/tun/sys.rs`.

## What goes on it, and what does not

The adapter carries the two addresses Cloudflare assigned — the inside of the tunnel — and nothing
else. It is given an MTU of **1280**, matching the stock client, and **no default route**.

Only traffic meant for the tunnel is routed here, by host routes this module installs. A packet
arriving from Windows therefore already carries the right source address and needs no rewriting on
the way out. A network stack on this side would exist only to undo work Windows already did.

The v6 address goes on whether or not anything is routed over it yet. It costs nothing while no v6
prefix points here, and it has to already be in place the moment one does.

## Ownership

The adapter is owned by this process. Dropping it removes it from Windows, and the routes go with
it. Nothing survives the process to be swept up later.

That has a consequence worth stating plainly: **a crashed core leaves no adapter and no routes** —
but it does leave the [name policy rule](names.md), which is why every command sweeps for one before
doing anything else.

## The name

`ADAPTER_NAME = "masqr"`, used as both the adapter name and its description. The name matters beyond
display: Wintun derives the adapter's GUID from it, and anything sweeping for adapters of ours
matches on that GUID rather than on the displayed name, which Windows may hand out localised.

### `ERROR_ALREADY_EXISTS` has two causes and one right answer each

- **The previous process is on its way out.** Wintun ties the adapter to its creating process; when
  that process exits, Windows removes the device *asynchronously*, so the name stays taken for a
  moment after the process is gone. A restart fast enough meets its own leftover.

  `create_waiting` handles this: it retries for `NAME_RELEASE_BUDGET` (8 s) every
  `NAME_RELEASE_POLL` (250 ms). Waiting is right *because* the removal is one Windows is already
  performing. Only error 183 is waited on — never an access denial, which would mean the process is
  not elevated and no amount of waiting fixes it.

- **An orphan is still running.** Nothing is on its way out, so waiting cannot help. That one is the
  supervisor's to solve, by killing the orphan before starting a new core.

## Routes

`Routes::apply` takes the whole wanted set and makes the table agree with it, returning what
changed. It is idempotent — applying the same set twice moves nothing — so the
application hand over the full set on every edit rather than computing a difference itself.

The set the core installs is the union of two halves, held under one lock in `core::Core`:

- what the application asked for over [`routes`](../reference/control-pipe.md#routes), and
- one host route per address currently [leased](dns.md#leases) by the resolver.

A v6 prefix survives that union only if the application asked for IPv6 **and** the tunnel was
measured carrying it. A name that resolved to an AAAA is still answered with that AAAA — it simply
goes out over the line, which is where it went before any of this existed.

## Reading and writing

Wintun permits one reader and one writer at a time. `Session::split` hands out the two halves
separately for exactly that reason: the reader goes to a blocking thread, the writer to the task
that drains the tunnel. The rule is expressed in the types rather than left to a comment.

The reader blocks. Wintun signals readability through an event, and a dedicated thread waiting on it
is both the documented way to use it and the cheapest.

## The shutdown contract

This is the part of the module where the order is the behaviour, and it was learned the expensive
way: **fifty stops under traffic, fifty access violations.**

Ending the session does make a blocked reader's wait return.
But ending a session while another thread is inside it is exactly what Wintun forbids, and a reader
that was mid-`receive` rather than mid-`wait` **is** inside it. Waking the reader that way is not a
race that sometimes bites; it is the crash.

So the session carries a second, manual-reset **quit event**, and the reader waits on both:

```rust
let waiting = [self.session.read_event, self.session.quit];
let woke = unsafe { WaitForMultipleObjects(2, waiting.as_ptr(), 0, WAIT_FOREVER) };
if woke != WAIT_OBJECT_0 { return None; }   // anything but a packet means leave
```

Stopping is setting that event, which touches nothing the driver owns. The order is then the only
correct one:

```text
stop watching the line      drop the interface-change watch first, or a late callback
        │                   asks a tunnel that is going away to check itself
        ▼
stop_reading()              set the quit event
        ▼
wait for the reader         it returns having touched nothing the driver owns
        ▼
close()                     WintunEndSession, once, with nobody inside it
        ▼
drop the adapter            WintunCloseAdapter; the routes go with it
```

`main.rs` prints a line at each step at `debug` level, so a failed shutdown names the call it did
not get past instead of leaving it to be inferred. If the reader does not return within
`READER_HANDOVER`, the process exits and leaves the adapter to Windows — a leftover device Windows
will clean up beats an access violation that leaves one behind *and* takes the process down before
it can say so.

Our integration tests and manual testing cycles prove this: bringing the core up and down repeatedly with requests in flight succeeds cleanly with a zero exit status and nothing left behind. See
[testing](../guide/testing.md).

## Talking to Windows

Two groups of calls, from different places for different reasons:

- **`wintun.dll` is loaded at run time**, not linked. It is a file shipped next to the binary, there
  is no import library to link against, and a missing DLL has to be a message rather than a process
  that will not start.
- **The IP Helper calls are linked normally** through `windows-sys`. They give the adapter its
  address, its MTU and its routes. The alternative is spawning `netsh`, which costs about a second
  per call and reports failure as text.
