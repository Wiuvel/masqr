<p align="center">
  <img src="./docs/images/brandIdentity.png" alt="masqr" width="50%" />
</p>

<p align="center">
  <b>A purpose-built MASQUE/WARP tunnel core for Windows, written in Rust</b>
</p>

It carries the addresses it is told to carry through WARP, and it answers the machine's DNS
itself — so a target enters the tunnel the moment its name resolves, rather than because somebody 
resolved it earlier. It is driven over a named pipe, so what it carries changes on a live tunnel 
with nothing to restart.

## Commands

```text
masqr version            print the version and exit
masqr register           register a device, or report the one already registered
masqr probe              open the tunnel and resolve a name through it
masqr up                 bring the adapter up and carry packets until stopped
masqr names              leave the machine resolving names as it did, and exit

  --identity   <path>    where the registered device is kept (default: identity.json)
  --wintun     <path>    which wintun.dll to load (default: beside this binary)
  --target     <prefix>  route this prefix into the tunnel; may be repeated
  --dns-listen <addr>    answer DNS here, once a policy is installed over the pipe
  --handshake  <mode>    connection handshake strategy: named, fronted, split, split-slow, no-sni
  --sni        <domain>  the SNI domain used for fronted or split handshakes
  --log-level  <level>   error | warn | notice | info | debug (default: info)
```

`up` needs to run elevated — creating a network adapter does. While it runs, `\\.\pipe\masqr` takes
one JSON object per line: what the tunnel is doing, what goes through it, the name policy, the log
level, reconnect, stop.

## Building

```powershell
cargo build --release
```

Needs the toolchain named in `rust-toolchain.toml`; the target is pinned in `.cargo/config.toml`.
`wintun.dll` is not built here — the core loads it from beside the binary or from `--wintun`.

## Documentation

[`docs/README.md`](docs/index.md) — architecture, the control-pipe protocol, the command line, the
design decisions, and what this core deliberately does not do.

`cargo doc --no-deps --open` renders the source: every module starts with why it exists and what it
refuses to do.

## License

This project is dual-licensed under either the [MIT License](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.
