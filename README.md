# Beastinator
> Beastinator, The Modern FreeBSD malware analysis and security audit tool made for your safety!


<div align="center">

<img src="assets/banner.svg" alt="Project Name — C & Rust" width="100%" />

<br/>

<!-- Shields.io badges -->
[![C](https://img.shields.io/badge/C-C11-A8B9CC?style=for-the-badge&logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Rust](https://img.shields.io/badge/Rust-1.70+-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Build](https://img.shields.io/github/actions/workflow/status/USER/REPO/ci.yml?style=for-the-badge&label=CI)](https://github.com/USER/REPO/actions)
[![Release](https://img.shields.io/github/v/release/USER/REPO?style=for-the-badge&color=blueviolet)](https://github.com/USER/REPO/releases)
[![Stars](https://img.shields.io/github/stars/USER/REPO?style=for-the-badge&color=gold)](https://github.com/USER/REPO/stargazers)

<br/>

> **A dual-implementation toolkit.** Reference C11 core, safe Rust rewrite.
> Byte-for-byte compatible. Same tests. Same output.

</div>

---

## ▍ Overview

A short paragraph on what the project does, and why there are two
implementations (embedded portability in C, memory safety + concurrency in Rust).
Both are kept behavior-compatible and pass the same fixture suite.

| Implementation | Language | Source       | Binary              |
|:---------------|:--------:|:-------------|:--------------------|
| Reference      | C11      | `src/c/`     | `build/app`         |
| Rewrite        | Rust     | `src/rust/`  | `target/release/app`|

---

## ▍ Installation

### 🅲 From source — C

```sh
git clone https://github.com/USER/REPO.git
cd REPO
make -C src/c
sudo make -C src/c install        # optional
```

### 🦀 From source — Rust

```sh
git clone https://github.com/USER/REPO.git
cd REPO/src/rust
cargo build --release
cargo install --path .            # optional
```

---

## ▍ Usage

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

## ▍ API Reference

### C API — `include/app.h`

```c
/* Initialize the library. Returns 0 on success, -1 on error. */
int app_init(const char *config_path);

/* Process a buffer in place. Returns the number of bytes written. */
size_t app_process(uint8_t *buf, size_t len, unsigned flags);

/* Tear down and free resources. */
void app_shutdown(void);
```

### Rust API — crate `app`

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

## ▍ Building & Testing

```sh
# C test suite
make -C src/c test

# Rust test suite
cargo test --manifest-path src/rust/Cargo.toml

# Parity check: both implementations must agree on fixtures
./scripts/parity-check.sh
```

---

<div align="center">

<sub>
Built with <b>C</b> and <b>Rust</b> · MIT Licensed · <a href="LICENSE">LICENSE</a>
</sub>



!HACKER's NOTE!
1. cc -Wall -Wextra -O2 -c parser.c -o parser.o
2. cc -Wall -Wextra -O2 parser.c syssec.c -o syssec
3. ./syssec , for verbose: ./syssec -v, to save report: ./syssec -o FILE
4. example execution: ./syssec -v -o report.html
5. for unaccessed sections of the report parsing, use elevated user, i.e. root: doas ./syssec -v -o report.html
6. to configure doas, write "permit persist :wheel" OR for a specific user "permit persist john" in the conf file located in /usr/local/etc/doas.conf

</div>
