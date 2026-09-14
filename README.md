# Beastinator
> Beastinator, The Modern FreeBSD malware analysis and security audit tool made for your safety!


<div align="center">

# Beastinator

**A dual-implementation toolkit — reference C11 core, safe Rust rewrite.**

[![C](https://img.shields.io/badge/C-C11-A8B9CC?style=for-the-badge&logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Rust](https://img.shields.io/badge/Rust-1.70+-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-4EAA25?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/USER/REPO)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge)](CONTRIBUTING.md)

</div>

---

## Overview

A short paragraph on what the project does, and why there are two
implementations. Both are kept behavior-compatible and pass the same fixtures.

| Implementation | Language | Source      | Binary               |
|:---------------|:--------:|:------------|:---------------------|
| Reference      | C11      | `src/c/`    | `build/app`          |
| Rewrite        | Rust     | `src/rust/` | `target/release/app` |

---

## Installation

### C — from source

```sh
git clone https://github.com/USER/REPO.git
cd REPO
make -C src/c
sudo make -C src/c install        # optional
```

### Rust — from source

```sh
git clone https://github.com/USER/REPO.git
cd REPO/src/rust
cargo build --release
cargo install --path .            # optional
```

---

## Usage

```sh
# C build
./build/app --input file.txt --output out.txt

# Rust build
./target/release/app --input file.txt --output out.txt
```

### CLI flags

```
Usage: app [OPTIONS] <INPUT>

Arguments:
  <INPUT>              Path to the input file

Options:
  -o, --output <PATH>  Write result to PATH instead of stdout
  -v, --verbose        Increase log verbosity (repeatable)
  -q, --quiet          Suppress non-error output
  -h, --help           Print help
  -V, --version        Print version
```

---

## API Reference

### C — `include/app.h`

```c
/* Initialize the library. Returns 0 on success, -1 on error. */
int app_init(const char *config_path);

/* Process a buffer in place. Returns the number of bytes written. */
size_t app_process(uint8_t *buf, size_t len, unsigned flags);

/* Tear down and free resources. */
void app_shutdown(void);
```

### Rust — crate `app`

```rust
use app::{Config, Processor};

/// Process a slice of bytes and return the transformed output.
pub fn process(input: &[u8], cfg: &Config) -> Result<Vec<u8>, app::Error>;

// Example
let cfg = Config::default();
let out = app::process(b"hello", &cfg)?;
assert_eq!(out, b"HELLO");
```

---

## Building & Testing

```sh
# C test suite
make -C src/c test

# Rust test suite
cargo test --manifest-path src/rust/Cargo.toml

# Parity check — both implementations must agree on fixtures
./scripts/parity-check.sh
```

---

## License

MIT — see [LICENSE](LICENSE).

!HACKER's NOTE!
1. cc -Wall -Wextra -O2 -c parser.c -o parser.o
2. cc -Wall -Wextra -O2 parser.c syssec.c -o syssec
3. ./syssec , for verbose: ./syssec -v, to save report: ./syssec -o FILE
4. example execution: ./syssec -v -o report.html
5. for unaccessed sections of the report parsing, use elevated user, i.e. root: doas ./syssec -v -o report.html
6. to configure doas, write "permit persist :wheel" OR for a specific user "permit persist john" in the conf file located in /usr/local/etc/doas.conf

