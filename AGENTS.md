# AGENTS.md

## Project Overview

Rust bindings to [libtailscale](https://github.com/tailscale/libtailscale), the C library for embedding Tailscale as a userspace network into your application. This crate lets Rust programs join a tailnet, listen for connections, dial other nodes, and use the LocalAPI.

## Repository Structure

```
├── src/lib.rs                  # Safe Rust wrapper (the `libtailscale` crate)
├── libtailscale-sys/           # FFI sys crate (`libtailscale-sys`)
│   ├── src/lib.rs              # Raw C FFI declarations
│   ├── build.rs                # Build script: compiles Go → C archive via `go build -buildmode=c-archive`
│   └── libtailscale/           # Git submodule of github.com/tailscale/libtailscale (Go + C source)
│       ├── tailscale.h         # Canonical C API header (source of truth for API surface)
│       ├── tailscale.go        # Go implementation with `//export` CGo functions
│       └── ...
├── examples/                   # Usage examples (echo_server, echo_client, http_echo_server)
├── Cargo.toml                  # Workspace root, defines the `libtailscale` crate
└── .github/workflows/CI.yml    # CI: test on Linux + macOS, rustfmt check
```

## Build Requirements

- **Rust** (stable)
- **Go 1.20+** — the sys crate's build script invokes `go build -buildmode=c-archive` to compile the Go library into a static C archive, then links it into Rust.
- Submodules must be initialized: `git submodule update --init --recursive`

## Architecture & Key Conventions

### Two-crate design

- **`libtailscale-sys`**: Raw `extern "C"` FFI declarations matching `tailscale.h`. This crate has a `build.rs` that cross-compiles the Go code and links the resulting static archive. When adding new FFI functions, add them here to match the C header signatures exactly.
- **`libtailscale`** (workspace root): Safe Rust API wrapping the sys crate. Provides `Tailscale`, `Listener`, `Loopback`, and `Incoming` types. All C error handling is done via the private `last_error()` method which calls `tailscale_errmsg`.

### API coverage

The Rust bindings should cover **every function** declared in `libtailscale-sys/libtailscale/tailscale.h`. When the upstream C API adds new functions, both crates need updating:
1. Add the `extern "C"` declaration to `libtailscale-sys/src/lib.rs`
2. Add a safe wrapper method to `src/lib.rs`

### Error handling pattern

All C functions return `0` on success or `-1` (or `EBADF`/`ERANGE`) on error. The Rust wrapper:
- Calls the FFI function
- Checks `ret != 0`
- On error: calls `self.last_error()` (which calls `tailscale_errmsg`) and returns `Err(String)`
- On success: returns `Ok(...)` with parsed/converted values

### File descriptors

Connections (`tailscale_conn`) and listeners (`tailscale_listener`) are raw file descriptors (`c_int`). The safe wrapper converts connections to `std::net::TcpStream` via `FromRawFd`. Listeners are closed via `libc::close` in their `Drop` impl.

### Cross-compilation

The `build.rs` handles cross-compilation by mapping Rust target triples to `GOOS`/`GOARCH` environment variables and configuring `CC`/`CXX` for CGo.

## Development Commands

```bash
cargo check                  # Type-check both crates
cargo check --examples       # Type-check examples too
cargo test --all             # Run tests (requires Go toolchain)
cargo fmt --all              # Format code
cargo fmt --all --check      # Check formatting (CI runs this)
```

## CI

GitHub Actions runs on `ubuntu-latest` and `macos-latest`:
- `cargo test --all` (with Go 1.20+)
- `cargo fmt --all --check`
