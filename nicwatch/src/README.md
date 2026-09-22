# nicwatch

**A live network interface monitor for FreeBSD and Linux.** `top` for your NIC.

`nicwatch` captures packets directly from the kernel — via `/dev/bpf` on
FreeBSD and `AF_PACKET` on Linux — aggregates them into rolling per-flow and
per-host views, and renders the whole thing in a self-refreshing ratatui TUI.
It's the statistics side of Wireshark without the hex dump.

## Features

- **Native capture, no libpcap.** FreeBSD: raw `/dev/bpf` ioctls.
  Linux: `AF_PACKET` raw socket via `nix`.
- **Rolling bandwidth graphs** — RX/TX rates, packets/sec, sparkline history.
- **Per-flow table** — every 5-tuple, sorted by bytes, with TCP flags and app hints.
- **Per-host table** — every IP we've seen, with MAC, byte counters, age.
- **Per-MAC table** — L2 neighbours, broadcast and multicast peers.
- **Protocol breakdown** — L3 (IPv4/IPv6/ARP), L4 (TCP/UDP/ICMP/…), app classifier.
- **Live packet ticker** — the last N packets as they arrive, `top`-style.
- **Kernel counters** — errors, drops, collisions.
- **Synthetic source** — deterministic traffic for demos and CI, no root needed.
- **Pause, tab switching, sort modes, help overlay** — keyboard-driven.

## Platform support

| Feature | FreeBSD | Linux |
|---|---|---|
| Live capture | `/dev/bpf` | `AF_PACKET` raw socket |
| Promiscuous mode | `BIOCPROMISC` | `PACKET_MR_PROMISC` |
| Read timeout | `BIOCSRTIMEOUT` | `SO_RCVTIMEO` |
| Interface stats | `ifmib` sysctl | `/sys/class/net/<if>/statistics/` |
| MAC discovery | `ifconfig <if>` | `/sys/class/net/<if>/address` |
| Direction inference | source MAC | source MAC |
| Synthetic source | ✓ | ✓ |
| TUI | ✓ | ✓ |

Both platforms need **root** or a specific capability to open a capture
socket — FreeBSD requires read access to `/dev/bpf`, Linux requires
`CAP_NET_RAW`.

## Requirements

- **FreeBSD 13.0+** or **Linux 5.10+**.
- **Rust 1.79 or newer.**
- On FreeBSD: read access to `/dev/bpf*`.
- On Linux: `CAP_NET_RAW` (or root).

## Install

```sh
git clone https://github.com/your-org/nicwatch
cd nicwatch
cargo build --release
sudo install -m 0755 target/release/nicwatch /usr/local/bin/nicwatch
```

## Usage

```
nicwatch [OPTIONS]

  -i, --interface <IF>       interface to monitor (default: autodetect)
  -w, --window <DUR>         rate sliding window       [default: 5s]
      --refresh <DUR>        snapshot cadence         [default: 250ms]
      --recent <N>           recent-packet ring size  [default: 4096]
      --no-promisc           do not put the NIC into promiscuous mode
      --synthetic <MODE>     mixed | http | scan | idle
      --list                 list interfaces and exit
      --probe                print the resolved backend and exit
  -h, --help                 show this help
```

### Examples

Autodetect and monitor:

```sh
sudo nicwatch
```

Monitor a specific interface:

```sh
# FreeBSD
sudo nicwatch -i em0

# Linux
sudo nicwatch -i eth0
```

Verify which backend will be used:

```sh
nicwatch -i eth0 --probe
# backend=af_packet interface=eth0 link_type=Ethernet
```

Try the TUI without root using synthetic traffic:

```sh
nicwatch --synthetic mixed
```

## Linux capability setup

Instead of running as root every time, grant the binary `CAP_NET_RAW`:

```sh
sudo setcap cap_net_raw+ep /usr/local/bin/nicwatch
```

Then a normal user can capture:

```sh
nicwatch -i eth0
```

To revoke:

```sh
sudo setcap -r /usr/local/bin/nicwatch
```

Note: `setcap` requires the binary to live on a filesystem mounted without
`nosuid` and with `xattr` support. `/usr/local/bin` on most distros qualifies.

## FreeBSD devfs setup

To grant a group access to `/dev/bpf` without sudo:

```
# /etc/devfs.rules
[nicwatch=10]
add path 'bpf*' mode 0660 group wheel
```

Then add `devfs_system_ruleset="nicwatch"` to `/etc/rc.conf`, run
`service devfs restart`, and add your user to `wheel`.

## Key bindings

| Key | Action |
|---|---|
| `q` / `Ctrl-C` | quit |
| `Space` | pause / resume |
| `1`..`5` | jump to tab (Overview, Flows, Hosts, Protocols, Live) |
| `Tab` / `Shift-Tab` | next / previous tab |
| `j` / `k` | scroll down / up in the current table |
| `PgUp` / `PgDn` | page through the table |
| `s` | cycle sort mode (bytes / packets / name) |
| `?` / `h` | toggle the help overlay |

## Architecture

```
        ┌───────────────────────────────────────────────────────────┐
        │  capture thread (sync, platform-specific)                 │
        │                                                           │
        │   FreeBSD:  /dev/bpf  →  ioctl(BIOCSETIF) → read(2)       │
        │   Linux:    AF_PACKET →  bind(ifindex)    → recvfrom(2)   │
        │                                                           │
        │  Both implement CaptureBackend::read_batch().             │
        └─────────────────────────┬─────────────────────────────────┘
                                  │  tokio::mpsc  (bounded, drop-on-full)
                                  ▼
        ┌───────────────────────────────────────────────────────────┐
        │  ingest task (platform-neutral)                           │
        │  Aggregator::ingest()  ·  DashMap-sharded, lock-free path │
        └─────────────────────────┬─────────────────────────────────┘
                                  │  watch<Snapshot> @ refresh interval
                                  ▼
        ┌───────────────────────────────────────────────────────────┐
        │  ratatui UI task (platform-neutral)                       │
        │  redraw @ 4 Hz  ·  crossterm key events                   │
        └───────────────────────────────────────────────────────────┘
```

The platform seam is **`CaptureBackend`**. Everything above it — parsing,
aggregation, protocol classification, TUI, synthetic source — is written once
and compiled for both targets.

### Capture backend selection

`src/capture/mod.rs` exposes `open_default(iface, promisc) -> Box<dyn
CaptureBackend>`. Under the hood it selects the correct impl at compile time
via `#[cfg(target_os = "...")]`. The rest of the program never names `Bpf` or
`AfPacket` directly.

### Direction inference

Neither BPF nor `AF_PACKET` tells us whether a frame was received or
transmitted. `nicwatch` resolves the interface's own MAC at startup and
classifies each frame: if the source MAC equals ours, it's TX; otherwise RX.
This is the same heuristic `tcpdump -Q in|out` uses internally.

### Advanced Rust bits

- **`CaptureBackend` trait object** behind a single `Box<dyn>` — the platform
  dispatch happens exactly once, at startup. The hot path is monomorphic.
- **Const-generic ring buffer** (`SlidingWindow<T, const CAP: usize>`) —
  stack-allocated, `std::array::from_fn` init, no allocation on ingest.
- **Newtypes with `#[repr(transparent)]`** — `MacAddr`, `Counters`,
  `TcpFlags` are zero-cost wrappers carrying their own semantics.
- **Zero-copy parsing** — `etherparse` slices into the captured buffer
  directly. The only per-packet allocation is the `Frame` struct.
- **Cross-platform sysctl shims** — `src/capture/stats.rs` uses `#[cfg]` to
  pick between `ifmib` and `/sys/class/net`. Both expose the same `IfStats`
  type so nothing downstream cares.

## Performance notes

- The capture read buffer is requested at **4 MiB** on both platforms. On a
  10 GbE link, bump `REQUESTED_BUFFER` in `backend_freebsd.rs` and
  `AfPacketConfig::buffer_size` in `backend_linux.rs` to 16 MiB or more.
- The ingest channel is bounded at **16 384 frames**. If the aggregator can't
  keep up, new frames are dropped — the `IfaceWindow` will show a discrepancy
  between `rx_total` and the kernel's `errors.rx_drops` if this happens.
- On Linux, `recvfrom` is called in a drain loop until `EAGAIN`; the kernel
  ring is generous by default, and `SO_RCVBUF` is enlarged to 4 MiB. This
  matches BPF's behavior and keeps syscall overhead proportional to packets,
  not to time.
- `--recent` bounds the Live tab's ring. On a busy 10 GbE link, 4096 frames
  is about 60 ms of history; raise it if you need more.

## Troubleshooting

### FreeBSD

**`capture: cannot open any /dev/bpf*: Permission denied`**
Run with `doas`/`sudo`, or configure `devfs.rules` as shown above.

**`interface "em0" not found`**
Run `nicwatch --list`. On FreeBSD, interfaces may be `igb0`, `re0`, `bge0`, etc.

### Linux

**`capture: socket(AF_PACKET): Operation not permitted`**
Grant `CAP_NET_RAW`: `sudo setcap cap_net_raw+ep /usr/local/bin/nicwatch`,
or run with `sudo`.

**`interface "eth0" not found`**
Run `nicwatch --list` or `ip link show`. Modern systems may use
`enp3s0`, `wlp2s0`, `eno1`, etc.

**No traffic despite a busy NIC**
Confirm the NIC is up (`ip link show eth0`), that you're not in a namespace
where the interface is invisible, and that `--no-promisc` isn't set.

**`/sys/class/net/<if>/speed` reports `-1`**
This is normal for virtual interfaces (lo, docker0, bridges) and for many
wireless drivers. `nicwatch` treats negative speed as "unknown baudrate"
and disables utilization calculation for that interface.

### Both

**`Live tab shows fewer packets than expected`**
The `--recent` ring is bounded. Older frames are evicted by design —
`nicwatch` is a monitor, not a capture-to-disk tool. If you need a pcap,
use `tcpdump` alongside it.

**The TUI doesn't render in a non-interactive shell**
`nicwatch` requires a TTY. Pipe to `cat` or redirect, and crossterm's
`EnterAlternateScreen` will fail. Use `--synthetic` in CI to smoke-test the
pipeline without a terminal, or run under `tmux`/`screen`.

## License

BSD 2-Clause. See `LICENSE` for the full text.
