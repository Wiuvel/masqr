# Building

```powershell
cargo build --release
```

The binary lands at `target\x86_64-pc-windows-msvc\release\masqr.exe`.

## What is pinned, and why it matters

Two files decide what comes out, and both fail quietly when they are not honoured:

- **`rust-toolchain.toml`** names the toolchain (`1.95.0`) and the components (`clippy`, `rustfmt`).
  A tree built without rustup installed uses whatever `cargo` happens to be on the path, and nothing
  says so.
- **`.cargo/config.toml`** pins the target to `x86_64-pc-windows-msvc`. An override in the
  environment produces a working binary for the wrong machine, and the only symptom is that it will
  not start on the machine it was meant for.

So a build is worth checking rather than assuming:

```powershell
rustc --version                     # matches rust-toolchain.toml
cargo build --release --locked      # --locked: Cargo.lock is not silently updated
.\target\x86_64-pc-windows-msvc\release\masqr.exe version
```

The last line is the one an inventory records. A binary reporting a version nobody expected is how an
inventory quietly stops matching the tree it describes.

## The release profile

```toml
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

Whole-program optimisation and one codegen unit, because this is built once and run for hours;
stripped, because a symbol table on a shipped binary buys nothing.

## `wintun.dll` is not built here

It is a redistributable from WireGuard LLC, and it is not copied into the build output either. The
core loads it from beside the binary or from `--wintun` — see [running](running.md). An application
shipping this core ships its own copy and points the core at it.

## Before committing

```powershell
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps
```

`clippy` is expected to be clean at `-D warnings`, not merely quiet at the default level. Every
module carries documentation and `cargo doc` is expected to build without warnings, because the
module docs are half of [the documentation](../README.md#conventions) and a broken intra-doc link is
a silently dead cross-reference.

## Where a build goes wrong

| Symptom | Cause |
| ------- | ----- |
| Links fail against `windows-sys` symbols | A feature missing from the `windows-sys` list in `Cargo.toml`; every call is behind one. |
| `rustls` panics at start with "no provider" | The `ring` provider is installed explicitly in `main`; a library embedding the crate has to do the same before building any config. |
| The binary starts and immediately reports it cannot find `wintun.dll` | Expected — it is loaded at run time on purpose, so a missing DLL is a message rather than a process that will not start. |
