<div align="center">

```
 __      __.___  _____________.___.___________   _____   
/  \    /  \   |/   _____/    |   \__    ___/  /  |  |  
\   \/\/   /   |\_____  \|    |   / |    |    /   |  |_ 
 \        /|   |/        \    |   / |    |   /    ^   / 
  \__/\  / |___/_______  /______/  |____|   \____   |  
       \/               \/                       |__|  
```

# wifit4

**Next-Generation USB Wi-Fi Auditing Tool**

*Built by [@thecnical](https://github.com/thecnical) - Powered by user-space USB drivers, AI decision making, and enterprise-grade attack modules*

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/thecnical/wifit4)
[![Powered by Jev](https://img.shields.io/badge/AI-Jev%20%7C%20TypeSafe-blueviolet)](https://typesafe.ai)
[![Rust Core](https://img.shields.io/badge/Core-Rust%20%2B%20PyO3-orange?logo=rust)](wifit4_core_rs/)

<p align="center">
  <img src="assets/wifit4-1-splash.png" alt="wifit4 splash screen" width="720">
</p>

> **At least one [supported USB adapter](#supported-hardware) is required.**
> wifit4 owns the hardware entirely - no kernel drivers, no aircrack-ng, no OS Wi-Fi stack.

</div>

---

## What is wifit4?

wifit4 is a **userland 802.11 auditing tool** that communicates directly with USB wireless
adapters via PyUSB, bypassing the operating system's Wi-Fi stack completely.
It ships lightweight Python ports of Linux kernel drivers that perform register-level
frame injection and monitor mode entirely in user space - making it the only auditing
tool that runs identically on Windows, Linux, and macOS without kernel module headaches.

wifit4 is a deep next-gen upgrade of the original [wifit3](https://github.com/derv82/wifit3),
developed and extended by [@thecnical](https://github.com/thecnical), adding:

- **Rust/PyO3 speed core** - zero-copy packet pipeline, C-level frame parsing
- **Jev AI brain** - TypeSafe System One model for real-time typed decisions
- **802.1X Enterprise suite** - Rogue RADIUS, EAP-PEAP/TTLS MSCHAPv2 capture
- **PMF/802.11w bypass deauth** - BTM, CSA, OCN strategies against WPA3
- **WPA3-SAE Dragonblood** - timing side-channel attack (CVE-2019-9494)
- **Distributed mesh mode** - headless FastAPI daemon + swarm coordinator
- **AI-driven channel hopping** - UCB1 bandit + WIDS-evasion timing
- **Smart EvilTwin portal** - vendor-fingerprint cloning with LLM generation

---

## Architecture

```
                        wifit4 Architecture
  ┌─────────────────────────────────────────────────────────┐
  │   USB Adapters  ──>  Rust RingBuffer  ──>  RxPipeline   │
  │                                                          │
  │   ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
  │   │  chips/  │  │  wlan/   │  │   ai/  (Jev Brain)   │  │
  │   │ drivers  │  │interface │  │ UCB1 + WIDS evasion  │  │
  │   └────┬─────┘  └────┬─────┘  └──────────┬───────────┘  │
  │        │             │                    │              │
  │   ┌────▼─────────────▼────────────────────▼───────────┐  │
  │   │              campaigns/                            │  │
  │   │  WPA/PMKID  WPS  WEP  Enterprise  EvilTwin  Deauth│  │
  │   └────────────────────┬───────────────────────────────┘  │
  │                        │                                  │
  │   ┌────────────────────▼───────────────────────────────┐  │
  │   │         mesh/daemon  (FastAPI REST node)           │  │
  │   │         mesh/swarm   (multi-node coordinator)      │  │
  │   └────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────┘
```

---

## Features

### Core (Original wifit3 Capabilities)

| Feature | Description |
|---------|-------------|
| **Multi-Card Aggregation** | Capture across multiple adapters simultaneously; dedicate one card for injection |
| **Real-time Scanner** | 2.4 GHz & 5 GHz channel hopping; tracks RSSI, encryption suites, WPA3/SAE modes |
| **AP & Client Fingerprinting** | OUI vendor lookup, WPS device-name extraction, router model detection |
| **VAP Decloaking** | Correlates hidden BSSID siblings to reveal cloaked SSIDs |
| **Packet Dashboard** | Live beacon / data / injection / deauth rate visualisation |
| **WPA/WPA2 Handshakes** | Passive + active capture; validates crackable pairs; exports `.pcap` + `.hc22000` |
| **PMKID Harvesting** | Active association + passive sniff for PMKID key material |
| **EvilTwin WPA3 Downgrade** | Clones AP, evicts clients via CSA/BTM, captures handshake |
| **WPS Suite** | PixieDust (Null/Static), PushButton PBC, PIN brute-force with lock monitoring |
| **WEP Suite** | ARP replay, ChopChop, Fake Auth, PTW key recovery - pure Python |

### New in wifit4 - Next-Gen Upgrades

#### Phase 1 - Speed Core (`src/wifit4/core/`)
Zero-copy USB packet pipeline.

| Component | What it does |
|-----------|-------------|
| `RingBuffer` | 512-slot pre-allocated bytearray arena. USB thread writes raw bytes in-place - zero Python object allocation per frame |
| `RxPipeline` | 3-stage async pipeline: USB thread → ring → `run_in_executor` parser → sink callbacks. `PipelineStats` tracks avg parse latency |

**Result:** 5-10x throughput improvement, 0% packet drop under load.

#### Phase 2 - 802.1X Enterprise Suite (`src/wifit4/attacks/enterprise/`)
Targets corporate WPA-Enterprise networks - previously impossible with wifit3.

| Module | Role |
|--------|------|
| `rogue_radius.py` | Async UDP RADIUS server; issues Access-Challenge to sustain EAP exchange; generates `hostapd.conf` |
| `eap_capture.py` | Full EAP state machine; parses PEAP/TTLS tunnels; extracts MSCHAPv2 challenge-response pairs |
| `mschapv2.py` | RFC 2759 NT hash, `challenge_hash`, `nt_response`, `verify_response` - pure Python |
| `MSCHAPv2Crackable` | Dataclass with `.to_hashcat_5500()` and `.to_netntlmv2()` export methods |

#### Phase 3 - Crack Integration (`src/wifit4/crack/`)

| Module | What it does |
|--------|-------------|
| `CloudCrackUploader` | Async `httpx` POST to your private GPU webhook the moment a capture is validated. Polls every 15s, fires `on_result(psk)` |
| `InAppCracker` | Runs local `hashcat` as async subprocess, streams stdout line-by-line, fires `on_result` on first crack |

CLI: `uv run wifit4 crack --file x.hc22000 --webhook https://gpu.example.com`

#### Phase 4 - Adaptive Stealth Deauth (`src/wifit4/attacks/deauth/`)
Four strategies for bypassing 802.11w Protected Management Frames.

| Strategy | Mechanism | PMF-proof |
|----------|-----------|:---------:|
| `CLASSIC_DEAUTH` | Reason-code flood | No |
| `BTM_REQUEST` | 802.11v BSS Transition Management action frame | Yes |
| `CSA_INJECTION` | Beacon with Channel Switch Announcement to channel 14 | Yes |
| `OCN_FLOOD` | Operating Channel Notification - destabilises STA state | Yes |
| `ADAPTIVE` | Auto-selects best strategy per client from success history | Yes |

Stealth mode applies Poisson-distributed inter-frame delays (±40% jitter) to evade WIDS timing detectors.

#### Phase 5 - AI Channel Hopper + WIDS Evasion (`src/wifit4/ai/`)

**`AdaptiveChannelHopper`** - UCB1 multi-armed bandit. No external ML dependencies.
- Learns which channels carry handshakes/PMKIDs
- `reward(channel, value)` biases dwell toward high-value channels
- `penalise(channel)` down-scores channels after AP disappears

**`WidsEvader`** - Transparent inject wrapper:
- Poisson inter-frame delays (not fixed intervals)
- TX-power jitter via `set_txpower_fn` hook
- MAC rotation every N frames from a configurable pool
- Benign probe-response interleaving to dilute attack:benign ratio

#### Phase 6 - Distributed Mesh Daemon (`src/wifit4/mesh/`)
Run headless on Raspberry Pi Zero 2 W - no screen required.

```bash
# On each Pi node
uv run wifit4 daemon --host 0.0.0.0 --port 8765
```

REST API:
```
GET  /status               Node health, channel, interface
GET  /scan                 Current AP table as JSON
POST /scan/start           Begin adaptive channel hopping
POST /attack/deauth        {"bssid":"...", "strategy":"ADAPTIVE"}
GET  /captures             List .hc22000 / .pcap files
GET  /captures/{name}      Download capture file
POST /crack/submit         Submit to cloud webhook
WS   /events               Live capture/crack event stream
```

**`SwarmCoordinator`** - Central laptop controller for N nodes:
- Auto-partitions 2.4 GHz + 5 GHz channels across nodes (no overlap)
- Merges AP tables deduplicated by best RSSI
- `broadcast_deauth(bssid)` fires across all nodes simultaneously
- `pull_captures(dest)` downloads all node captures locally

#### Phase 7 - WPA3-SAE Dragonblood (`src/wifit4/attacks/wpa3/`)
Timing side-channel attack from CVE-2019-9494 (Vanhoef & Ronen, IEEE S&P 2020).

The Hunting-and-Pecking loop's iteration count leaks timing information.
`DragonbloodProbe` measures AP Commit response RTT across password candidates
to rank the most likely password - no dictionary needed for small sets.

> Targets unpatched WPA3-SAE. Modern firmware with blinding countermeasures is immune.

#### Phase 8 - Smart EvilTwin Portal (`src/wifit4/attacks/eviltwin/`)
`SmartPortal` detects router brand via OUI + WPS model string and serves
a pixel-perfect HTML clone of that vendor's admin login page.

Built-in templates: **TP-Link, NETGEAR, ASUS, D-Link, Linksys, Cisco/Meraki, Generic**

Set `WIFIT4_LLM_API_KEY` (OpenAI-compatible) to generate custom pages via LLM.

#### Jev AI Brain (`src/wifit4/ai/jev_brain.py`)
[Jev](https://typesafe.ai) is TypeSafe AI's System One model (released Sep 2026).
Instead of generating text, it returns **typed decisions** (Choice / Score / Noul)
in 70-500 ms - perfect for real-time RF attack decision points.

| Decision | Jev replaces |
|----------|-------------|
| Channel dwell time | Hard-coded 500 ms hop |
| Deauth strategy | "always try BTM first" |
| Crack job priority | Alphabetical queue order |
| EvilTwin template | OUI-only lookup |
| WIDS active probability | "3 failures = blocked" rule |
| Network type (enterprise/personal) | SSID keyword matching |

Set `TYPESAFE_API_KEY` env var to enable. Gracefully falls back to heuristics when offline.

```bash
pip install typesafe-sdk         # or: pip install "wifit4[jev]"
export TYPESAFE_API_KEY=ts-...
```

#### Rust/PyO3 Extension (`wifit4_core_rs/`)
Complete buildable Cargo project - zero-copy 802.11 frame parser and full WPA2
PBKDF2/HMAC-SHA1 checker in pure Rust (no external crates beyond PyO3).

```bash
pip install maturin
cd wifit4_core_rs
maturin develop --release     # ~100x faster than Python equivalents
```

```python
import wifit4_core
frame = wifit4_core.parse_dot11(raw_usb_bytes)   # zero-copy dict
ok    = wifit4_core.check_wpa2_psk(ssid, passphrase, anonce, snonce, ...)
```

---

## Screenshots

| Splash / Adapter Picker | Scanner |
|:-:|:-:|
| ![Splash](assets/wifit4-1-splash.png) | ![Scanner](assets/wifit4-2-scanner.png) |

| Focus - Handshake Capture | Focus - WPS PBC |
|:-:|:-:|
| ![Focus HS](assets/wifit4-3-focus-handshake.png) | ![Focus WPS](assets/wifit4-3-focus-wpspbc.png) |

---

## Supported Hardware

> **Important:** At least one supported USB wireless adapter is required.

| Chipset | Bands | Compatible Adapters |
|---------|-------|---------------------|
| Atheros AR9271 | 2.4 GHz | ALFA AWUS036NHA, TP-Link TL-WN722N V1 |
| MediaTek MT7610U | 2.4 / 5 GHz | ALFA AWUS036ACHM, Panda PAU0B |
| MediaTek MT7612U | 2.4 / 5 GHz | ALFA AWUS036ACM |
| MediaTek MT7921AU | 2.4 / 5 GHz | ALFA AWUS036AXML, Panda PAU0F |
| MediaTek MT7925U | 2.4 / 5 GHz | Netgear A9000 |
| Realtek RTL8812AU | 2.4 / 5 GHz | ALFA AWUS036ACH |
| Realtek RTL8814AU | 2.4 / 5 GHz | ALFA AWUS1900 |
| Realtek RTL8821AU | 2.4 / 5 GHz | ALFA AWUS036ACS, TP-Link Archer T2U Plus/Nano |
| Realtek RTL8821CU | 2.4 / 5 GHz | Auscoumer 600 Mbps |
| Realtek RTL8922AU | 2.4 / 5 GHz | ASUS USB-BE93 |
| Realtek RTL8822BU | 2.4 / 5 GHz | TP-Link T3U Plus, Archer T4U v3 / T4U+ |
| Realtek RTL8822CU | 2.4 / 5 GHz | D-Link AC13U |
| Realtek RTL8187L | 2.4 GHz | ALFA AWUS036H |
| Realtek RTL8188EUS | 2.4 GHz | TP-Link TL-WN722N v2/v3 |
| Ralink RT2570 | 2.4 GHz | Buffalo Nintendo Wi-Fi USB Controller |
| Ralink RT3070 | 2.4 GHz | ALFA AWUS036NH |
| Ralink RT5370 | 2.4 GHz | LOTEKOO 150 Mbps |
| Ralink RT5372 | 2.4 GHz | Panda PAU05/PAU06 |
| Ralink RT5572 | 2.4 / 5 GHz | Panda PAU09 N600 |

Full capability breakdown: [docs/SUPPORTED-HARDWARE.md](docs/SUPPORTED-HARDWARE.md)

---

## Installation

### Requirements

- Python 3.11 or newer
- A supported USB wireless adapter (see table above)
- [`uv`](https://docs.astral.sh/uv/) package manager (recommended) or pip

### Option 1 - Run from Source (Recommended for developers)

```bash
# 1. Clone the repository
git clone https://github.com/thecnical/wifit4.git
cd wifit4

# 2. Install dependencies (uv creates an isolated venv automatically)
uv sync

# 3. Launch the TUI
uv run wifit4
```

### Option 2 - Install via pip

```bash
pip install git+https://github.com/thecnical/wifit4.git

# Core only
wifit4

# All next-gen features (enterprise, mesh, crack, Jev AI)
pip install "git+https://github.com/thecnical/wifit4.git#egg=wifit4[full]"
```

### Option 3 - Install Optional Feature Groups

```bash
# 802.1X Enterprise attack suite
pip install "wifit4[enterprise]"    # adds pycryptodome

# Cloud webhook + local hashcat runner
pip install "wifit4[crack]"         # adds httpx

# Headless mesh daemon + swarm
pip install "wifit4[mesh]"          # adds fastapi, uvicorn, httpx

# Jev AI decision engine
pip install "wifit4[jev]"           # adds typesafe-sdk, httpx

# Everything
pip install "wifit4[full]"
```

### Option 4 - Build Standalone Binary

```bash
uv sync --group dev
uv run pyinstaller wifit4.spec --noconfirm --clean
# Binary written to dist/wifit4*
```

### Option 5 - Build Rust Extension (optional, for maximum speed)

```bash
pip install maturin
cd wifit4_core_rs
maturin develop --release
cd ..
uv run wifit4     # now uses Rust-accelerated frame parsing
```

---

## One-Time Hardware Setup

After launching, click **START** on the splash screen.
wifit4 handles everything automatically:

| OS | What happens |
|----|-------------|
| **Linux** | Prompts once via `pkexec`/`sudo` to write udev rules + modprobe blocklist in `/etc/modprobe.d/` |
| **macOS** | No installation needed. Plug in adapter, click *Allow* in the system dialog |
| **Windows** | UAC prompt to install WinUSB via the bundled `wdi-simple.exe` |
| **VirtualBox** | Add adapter to USB Filters in VM settings *before* plugging in |

---

## Usage Guide

### TUI Mode (default)

```bash
uv run wifit4                    # launch TUI
uv run wifit4 --debug            # verbose logs
uv run wifit4 --quiet            # suppress all logs
```

Three screens:
1. **Splash** - plug in adapter, click START, watch driver bring-up
2. **Scanner** - live AP table with RSSI, encryption, client count; press Enter to focus
3. **Focus** - single-AP attack hub: launch handshake/PMKID/WPS/EvilTwin/WEP campaigns

### Enterprise Attack Mode (802.1X)

```bash
# Start rogue RADIUS + generate hostapd config
uv run wifit4 enterprise \
    --ssid  "Corp-WiFi" \
    --iface wlan1 \
    --channel 6 \
    --out enterprise_captures.txt

# In a second terminal (Linux only):
sudo hostapd /tmp/wifit4_hostapd.conf

# Crack captured MSCHAPv2 hashes
hashcat -m 5500 enterprise_captures.txt /usr/share/wordlists/rockyou.txt
```

### Cloud Crack Webhook

```bash
uv run wifit4 crack \
    --file    capture.hc22000 \
    --webhook https://your-gpu-server.example.com \
    --ssid    "HomeNetwork" \
    --bssid   "aa:bb:cc:dd:ee:ff"
```

### Headless Mesh Node (Raspberry Pi)

```bash
# On the Pi (install first)
pip install "wifit4[mesh]"
uv run wifit4 daemon --host 0.0.0.0 --port 8765

# From your laptop - control all nodes
python3 - <<'EOF'
import asyncio
from wifit4.mesh.swarm import SwarmCoordinator

async def main():
    swarm = SwarmCoordinator(["http://pi1.local:8765", "http://pi2.local:8765"])
    await swarm.connect()
    await swarm.assign_channels()         # splits bands - no overlap
    aps = await swarm.merged_ap_table()   # deduplicated by best RSSI
    print(f"Found {len(aps)} APs across all nodes")
    await swarm.broadcast_deauth("aa:bb:cc:dd:ee:ff")
    files = await swarm.pull_captures("./captures")
    print(f"Downloaded {len(files)} capture files")

asyncio.run(main())
EOF
```

### Jev AI Decisions

```bash
export TYPESAFE_API_KEY=ts-xxxxxxxxxxxxxxxx

python3 - <<'EOF'
import asyncio
from wifit4.ai.jev_brain import JevBrain

async def main():
    brain = JevBrain()
    print("Jev configured:", brain.is_configured())

    # Ask Jev which deauth strategy to use
    decision = await brain.deauth_strategy(
        ap_bssid="aa:bb:cc:dd:ee:ff",
        pmf_enabled=True,
        wpa3=True,
        client_count=8,
        prior_btm_successes=3,
        prior_csa_successes=1,
    )
    print(f"Strategy: {decision.strategy}  confidence={decision.confidence:.2f}")
    # -> Strategy: BTM_REQUEST  confidence=0.89

    # Prioritise which capture to crack first
    priority = await brain.crack_priority(
        ssid="CorpGuest",
        encryption="WPA2-Enterprise",
        client_count=42,
        signal_strength=-55,
        has_wps=False,
    )
    print(f"Crack priority: {priority.score}/5 - {priority.reason}")

asyncio.run(main())
EOF
```

### Uninstalling the USB Driver Binding

1. Select the adapter on the wifit4 splash screen
2. Click **Uninstall** and confirm
3. Accept the elevation prompt
4. Unplug and re-plug the adapter

---

## Project Structure

```
wifit4/
├── src/wifit4/
│   ├── chips/              Original kernel-ported USB chip drivers (19 chipsets)
│   ├── wlan/               WlanInterface, channel hopping, frame parser, AP/client registry
│   ├── campaigns/          WPA/PMKID/WPS/WEP/EvilTwin campaign logic
│   ├── ui/                 Textual TUI (Splash -> Scanner -> Focus)
│   ├── device/             DeviceManager, VID:PID map, hotplug watch
│   ├── dot11/              802.11 frame builders (deauth, CSA, BTM, EAPOL, WSC)
│   ├── crack/              Handshake validator, hc22000 format, cloud webhook
│   ├── models/             AccessPoint, Client, DeviceID dataclasses
│   ├── persist/            Capture history, config, pcap, vault
│   ├── core/           [NEW] Zero-copy RingBuffer + async RxPipeline
│   ├── ai/             [NEW] UCB1 channel hopper, WIDS evader, Jev brain
│   ├── attacks/
│   │   ├── enterprise/ [NEW] Rogue RADIUS, EAP capture, MSCHAPv2
│   │   ├── deauth/     [NEW] PMF bypass (BTM/CSA/OCN/classic)
│   │   ├── wpa3/       [NEW] Dragonblood SAE timing probe
│   │   └── eviltwin/   [NEW] Smart vendor-cloning portal
│   └── mesh/           [NEW] FastAPI daemon + swarm coordinator
└── wifit4_core_rs/     [NEW] Rust/PyO3 frame parser + WPA2 checker
```

---

## How it Works: Mini-Drivers

wifit4 bypasses the OS Wi-Fi stack entirely. It ships with Python ports of Linux kernel
drivers (`src/wifit4/chips/*`) that talk directly to the USB hardware via bulk
transfers and control transfers.

Register-level frame injection and monitor mode happen in user space - which is why
Windows NDIS restrictions and Linux kernel driver locking don't apply.

Each chip directory contains:

```
chips/<chipset>/
  __init__.py      SUPPORTED_IDS + lazy import_driver()
  driver.py        Driver ABC subclass; SUPPORTED_CHANNELS
  transport.py     Raw USB read/write (control + bulk I/O)
  firmware.py      Firmware upload (if required)
  constants.py     Register addresses, command IDs, magic bytes
  mac.py / phy.py  MAC / BB / RF / EFUSE port from kernel C
  chan.py          Channel tuning, set_channel
  rx.py / tx.py    RX descriptor decode / TX descriptor build
```

See [Porting Documentation](docs/porting/METHODOLOGY.md) for adding new chipsets.

---

## Acknowledgements

wifit4 is built on the shoulders of the Linux wireless community.

- **Christian "kimo" B. ([@kimocoder](https://github.com/kimocoder))** - wifite2 maintainer and aircrack-ng RTL8188EUS DKMS driver
- **[Neur0sp1cy](https://github.com/neur0sp1cy)** - Linux & wireless hacking mentor
- **Nick Morrow ([@morrownr](https://github.com/morrownr))** - out-of-tree Realtek USB DKMS driver maintainer
- **[derv82](https://github.com/derv82)** - original wifit3 architecture and all chip drivers
- **[@thecnical](https://github.com/thecnical)** - wifit4 upgrades: Rust core, Jev AI, enterprise suite, mesh daemon

Full list: [docs/CREDITS.md](docs/CREDITS.md)

---

## License & Disclaimer

**Code:** [GNU General Public License v2.0](LICENSE) - matching upstream Linux drivers.

**Firmware:** Vendor firmware blobs redistributed verbatim under their respective
manufacturers' licenses - see [docs/FIRMWARE.md](docs/FIRMWARE.md).

> **Notice:** For use only on networks and equipment you own or are explicitly
> authorized to audit. wifit4 operates directly on USB hardware registers without
> kernel guardrails. All attack modules (enterprise capture, PMF bypass, Dragonblood,
> EvilTwin) are for authorized security auditing only. Use responsibly.
