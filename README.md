# Beastinator Syssec

**A FreeBSD security audit and system inspection tool, written in Rust.**

Beastinator Syssec performs a comprehensive, non-invasive security scan of a FreeBSD system — users, processes, filesystem permissions, disks, devices, network sockets, kernel state, SSH configuration, SUID binaries, and binary integrity. It produces a human-readable console report, per-item verbose output, or a self-contained HTML report you can archive or share.

The original implementation was a C program using native BSD syscalls, see src/c; this is a full Rust rewrite using the `libc` crate for direct syscall access on `x86_64-unknown-freebsd` and `aarch64-unknown-freebsd`.

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Building from source](#building-from-source)
- [Installing](#installing)
- [Usage](#usage)
- [Example output](#example-output)
- [What SYSSEC checks](#what-syssec-checks)
- [HTML reports](#html-reports)
- [Exit codes](#exit-codes)
- [Privileges](#privileges)
- [Porting notes](#porting-notes)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **System inspection** — hostname, kernel version, CPU, memory, uptime, load average.
- **User auditing** — duplicate UIDs, unexpected UID 0 accounts, users with valid shells.
- **Filesystem hygiene** — permissions on `/etc/passwd`, `/etc/master.passwd`, `/etc/group`, `/etc/sudoers`; sticky-bit checks on `/tmp`, `/var/tmp`, `/usr/tmp`.
- **Disk and swap monitoring** — via `df -h`, `swapinfo -m`, and direct `ioctl(DIOCGMEDIASIZE)` on `/dev` device nodes.
- **Device and TTY analysis** — character/block device counts, world-writable device nodes, essential `/dev` entries, active TTY sessions.
- **Live network inspection** — TCP/UDP v4+v6 connections and listeners via `sockstat`, with suspicious-port detection, public-IP classification, and connection-state analysis.
- **Kernel security state** — `kern.securelevel`, ASLR, `net.inet.ip.forwarding`, and loaded kernel modules cross-checked against `/boot/kernel` and `/boot/modules`.
- **SSH configuration review** — `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`.
- **SUID/SGID scanning** — a full filesystem sweep compared against a whitelist of expected setuid binaries.
- **Binary integrity** — SHA-256 of ~120 standard FreeBSD utilities, cross-checked for existence, ownership, executable bit, and world-writability.
- **Deep tree parsing** — verbose per-entry listings of `/dev`, `/sys`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`.
- **Three output modes** — summary, verbose per-item, and critical-only.
- **HTML export** — a single self-contained file with embedded CSS.

---

## Requirements

- **FreeBSD 13.0 or later** (13.2, 14.x tested). Older 12.x builds should work but are untested.
- **Rust 1.70 or newer** — install via [rustup](https://rustup.rs/) if you don't have it:
  ```sh
  pkg install rust
  # or
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **`sha256` utility** — present on all FreeBSD base systems as `/sbin/sha256`.
- **Root privileges** — for the majority of checks (see [Privileges](#privileges)).

No third-party FreeBSD packages are required beyond the Rust toolchain.

---

## Building from source

Clone the repository:

```sh
git clone https://github.com/your-org/syssec.git
cd syssec
```

Build an optimized binary:

```sh
cargo build --release
```

On FreeBSD the default target triple is already `x86_64-unknown-freebsd` (or `aarch64-unknown-freebsd` on ARM), so no explicit `--target` is needed. If you're cross-compiling from Linux or macOS, install the FreeBSD target first:

```sh
rustup target add x86_64-unknown-freebsd
cargo build --release --target x86_64-unknown-freebsd
```

The resulting binary is at:

```
target/release/syssec
```

---

## Installing

Copy the binary somewhere on your `$PATH`:

```sh
doas install -m 0755 target/release/syssec /usr/local/bin/syssec
```

Or use `cargo install` (installs to `~/.cargo/bin` by default):

```sh
cargo install --path .
```

Verify the install:

```sh
syssec --help
```

---

## Usage

```
Usage: syssec [OPTIONS]

Options:
  -v, --verbose     Verbose output (per-item checks)
  -q, --quiet       Quiet mode
  -o, --output FILE Save HTML report to FILE
  -c, --critical    Show only critical issues
  -n, --network     Network only
  -N, --no-network  Skip network checks
  -h, --help        Show this help
```

### Common invocations

Standard scan with summary output:

```sh
doas syssec
```

Verbose per-item output — shows every check as it runs:

```sh
doas syssec -v
```

Save a self-contained HTML report:

```sh
doas syssec -o /var/log/syssec-$(date +%F).html
```

Only show critical failures — useful in a cron job or `motd` script:

```sh
doas syssec -c
```

Skip the network checks if you're running in a restricted or air-gapped context:

```sh
doas syssec -N
```

Run only the deep network inspection:

```sh
doas syssec -n
```

### Scheduled scans

Add to `/etc/cron.d/syssec` (or root's crontab) to run once a day and store an HTML report:

```
0 3 * * * root /usr/local/bin/syssec -q -o /var/log/syssec/$(date +\%F).html
```

Because `-q` suppresses banners and summaries, only the report file is written.

---

## Example output

A short run looks like this:

```
╔═══════════════════════════════════════════════════════════════╗
║                    SYSSEC - Security Scanner                      ║
║                    FreeBSD Security Audit                         ║
║                    Version 1.1.0                              ║
╚═══════════════════════════════════════════════════════════════╝

▸ System Information
    ✓ CPU                                      4 cores: AMD Ryzen 5
    ✓ Memory                                   16384 MB total
    ✓ Uptime                                   12 days, 04:31:22
    ✓ Load Average                             0.21, 0.34, 0.29

▸ Processes
    ✓ Process Count                            312 total (2 running, 308 sleeping, 2 zombie)

▸ User Accounts
    ✓ User Accounts                            19 users (3 with shell)
    ✓ UID 0 Users                              Only root has UID 0

...
```

With `-v`, the deep tree parsing phase prints every entry under `/dev`, `/sys`, and the `bin` tree:

```
═══════════════════════════════════════════════════════════════
  Parsing tree: /dev (max depth: 1)
═══════════════════════════════════════════════════════════════
  CHR  crw-rw-rw- uid=0 gid=0 null
  CHR  crw-rw-rw- uid=0 gid=0 zero
  CHR  crw-r--r-- uid=0 gid=0 random
  CHR  crw-r--r-- uid=0 gid=0 urandom
  ...
```

---

## What SYSSEC checks

| Category | Checks performed |
|---|---|
| **System** | CPU, memory, uptime, load average |
| **Processes** | Total count, zombie count, run-queue depth |
| **Users** | Duplicate UIDs, extra UID-0 accounts, shell-enabled accounts |
| **Filesystem** | Permissions on critical files; sticky bits on temp dirs |
| **Disks** | Per-mount usage %; swap usage %; per-disk media size |
| **Devices** | `/dev` inventory, world-writable device nodes, essential nodes |
| **Sysfs** | `/sys/devices`, `/sys/class`, `/sys/module` inventories |
| **TTY** | Active TTY sessions, suspicious TTYs without login |
| **Network** | Listening TCP ports, firewall presence, IP forwarding |
| **Network (deep)** | Every `sockstat` connection; suspicious ports; public-IP detection |
| **Services** | Critical daemons running; dangerous services (telnetd, ftpd, …) |
| **Security** | `kern.securelevel`, ASLR, hidden kernel modules |
| **SSH** | `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding` |
| **SUID** | All setuid/setgid binaries vs. a whitelist |
| **Logs** | Presence of standard syslog files |
| **Updates** | `freebsd-update` and `pkg` availability |
| **Integrity** | SHA-256 of ~120 standard binaries; ownership & mode checks |

Each check yields a severity (`Info`, `Warning`, `Critical`) and a status (`Pass`, `Warn`, `Fail`, `Unknown`). Only non-passing results produce recommendations.

---

## HTML reports

The `-o FILE` flag produces a single, self-contained HTML file:

- **No external CSS, fonts, or JavaScript.** Open it anywhere.
- **Colour-coded rows** — green for pass, yellow for warn, red for fail.
- **Grouped by category** with per-item recommendations shown in a highlighted block.
- **Summary bar** at the top with pass / warn / fail counts.

Suitable for emailing, archiving, or attaching to a ticket.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed, or only warnings. |
| `1` | At least one check **failed** (severity `Critical` with status `Fail`). |

Useful in scripts:

```sh
if ! doas syssec -c -q; then
    echo "syssec found critical issues" | mail -s "syssec alert" root
fi
```

---

## Privileges

SYSSEC runs as an ordinary user, but many checks return `Unknown` or are skipped without root:

| Root required | Reason |
|---|---|
| Kernel module enumeration (`kldnext`/`kldstat`) | Requires `kern.allowkmem` or root. |
| `kinfo_proc` full listing | Some fields are hidden from non-root. |
| `/etc/master.passwd` stat | Mode is `0600`. |
| Deep network (`sockstat`) | Needs to see all sockets. |
| Disk `ioctl(DIOCGMEDIASIZE)` | Needs read access to `/dev/da*`, `/dev/ada*`, etc. |

The scanner prints a warning at startup if it isn't running as root. For a complete audit, run with `doas` or `sudo`.

---

## Porting notes

This project is a direct Rust rewrite of a C codebase that used native BSD syscalls. A few things to know if you're comparing the two:

- **`__BSD_VISIBLE` and `_WANT_*` macros are gone.** They're preprocessor artifacts; the `libc` crate exposes the correct FreeBSD definitions automatically for the target triple.
- **Fixed-size arrays became `Vec<T>`.** The original `connections[2048]`, `ips[512]`, etc. are now growable vectors. The same capacity limits (`NET_MAX_CONNECTIONS`, `PARSER_MAX_ENTRIES`) still apply, but they're checked at push time instead of being a hard struct size.
- **`popen()` calls are replaced by `std::process::Command`.** Behaviour is identical; the arguments aren't passed through a shell unless required (`sh -c` for the pipe-based commands like `find | xargs`).
- **`sscanf`-based `sockstat` parsing is replaced by `split_whitespace` + `parse`.** This is more robust against long process names, which the original could silently truncate.
- **`kld_file_stat.version`** must be set to `KLD_FILE_STAT_SIZE` before calling `kldstat()`. If you're on a FreeBSD release where the struct layout has changed and you get a "no field" error, that's the first place to look.

---

## Project layout

```
src/
├── main.rs          # Argument parsing, dispatch, exit codes
├── colors.rs        # ANSI escape constants
├── syssec.rs        # Core Syssec struct, logging, sysctl helpers, result types
├── checks.rs        # All individual check functions
├── parser.rs        # Deep tree walker + binary integrity (SHA-256)
├── netinspect.rs    # Live network inspection (sockstat, alerts, diffs)
└── report.rs        # Banner, summary, results, HTML export
```

Each module corresponds to one source file from the original C project, so a side-by-side reading is straightforward.

---

## Troubleshooting

**`error: linking with 'cc' failed: exit status: 1`**

Rust on FreeBSD needs a working C linker for the final link step. Install `binutils` or the base `ld`:

```sh
pkg install binutils
```

**`sysctl: unknown oid 'kern.elf64.aslr.enable'`**

Some FreeBSD versions don't expose this knob. The check is skipped silently — nothing to do.

**`Cannot open /dev` or empty `/dev` output**

Running inside a jail without `devfs` mounted at `/dev`. Either mount it or run outside the jail.

**`Binary integrity check reports many MISSING entries`**

The standard-binary list targets a full FreeBSD base system. On a minimal install (e.g., NanoBSD or a hand-trimmed root), several entries legitimately won't exist. Add an exclusion list or ignore the warning.

**`Report saved to: ...` but the HTML is empty**

Check that the process had write permission to the target directory. The error message from `syssec_log!` goes to stderr.

---

## License

BSD 2-Clause. See `LICENSE` for the full text.

---

*SYSSEC is a read-only auditor. It does not modify system state, does not enforce policy, and does not perform remediation. Pair it with a real configuration-management or IDS tool for active defence.*
