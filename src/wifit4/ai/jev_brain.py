"""
Jev-powered decision engine for wifit4.

Jev (TypeSafe AI, September 2026) is a "System One" model - it returns
typed decisions (Choice / Score / Noul) in 70–500 ms with no free-form text.
It is ideal for real-time RF auditing because every decision point in the
attack pipeline is a bounded classification problem, not a generation problem.

SDK: pip install typesafe-sdk
API: POST https://api.typesafe.ai/v1/systemone
Auth: Authorization: Bearer <TYPESAFE_API_KEY>
Cost: $0.042 / million input tokens.  Output tokens: FREE.

How Jev replaces hard-coded heuristics in wifit4
─────────────────────────────────────────────────
  Hard-coded rule                   Jev replacement
  ─────────────────────────────     ──────────────────────────────────────────
  "Hop to next channel every 0.5s"  Score(ap_traffic_density) → dwell time
  "Try classic deauth first"        Choice(deauth_strategy) from AP profile
  "Wordlist order = alphabetical"   Score(password_entropy) → crack priority
  "EvilTwin always serves generic"  Choice(portal_template) from AP vendor
  "Assume WIDS after 3 rejects"     Noul(wids_active) from timing pattern
  "Enterprise if SSID has 'Corp'"   Choice(network_type) from beacon fields

All six integrations are implemented in this module.  Each wraps an async
method that accepts structured state and fires a Jev request, returning a
strongly-typed Python object your calling code branches on directly.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("wifit4.ai.jev")

_JEV_API_URL = "https://api.typesafe.ai/v1/systemone"
_JEV_MODEL   = "jev-latest"
_ENV_KEY     = "TYPESAFE_API_KEY"


# ---------------------------------------------------------------------------
# Typed result containers
# ---------------------------------------------------------------------------

@dataclass
class ChannelDwellDecision:
    channel: int
    dwell_ms: int          # how long to stay on this channel
    confidence: float      # 0–1 from Jev Score

@dataclass
class DeauthStrategyDecision:
    strategy: str          # "BTM_REQUEST" | "CSA_INJECTION" | "CLASSIC_DEAUTH" | "OCN_FLOOD"
    confidence: float
    probabilities: dict[str, float]

@dataclass
class CrackPriorityDecision:
    score: int             # 1–5 Jev Score
    confidence: float
    reason: str            # derived from score level

@dataclass
class PortalTemplateDecision:
    template_key: str      # "tplink" | "netgear" | "asus" | "cisco" | "generic" | ...
    confidence: float

@dataclass
class WidsDetectionDecision:
    wids_active: bool
    probability: float     # Jev Noul → probability WIDS is active

@dataclass
class NetworkTypeDecision:
    network_type: str      # "enterprise" | "personal" | "open" | "hotspot"
    confidence: float
    probabilities: dict[str, float]


# ---------------------------------------------------------------------------
# Jev client
# ---------------------------------------------------------------------------

class JevBrain:
    """
    Async Jev client integrating all six wifit4 decision points.

    Falls back gracefully to deterministic defaults when:
      - TYPESAFE_API_KEY is not set
      - typesafe-sdk is not installed
      - The API is unreachable (network error, 529 overload)

    This means the tool works perfectly offline; Jev enhances decisions
    when available but is never a hard dependency.
    """

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key or os.getenv(_ENV_KEY, "")
        self._sdk_available = self._check_sdk()
        self._call_count = 0
        self._error_count = 0

    def _check_sdk(self) -> bool:
        try:
            import typesafe  # noqa: F401
            return True
        except ImportError:
            try:
                import httpx  # noqa: F401 - fall back to raw httpx
                return True
            except ImportError:
                return False

    def is_configured(self) -> bool:
        return bool(self._api_key) and self._sdk_available

    # -- Decision 1: Channel dwell time --------------------------------------

    async def channel_dwell(
        self, channel: int, ap_count: int, packet_rate: float, target_bssids: list[str]
    ) -> ChannelDwellDecision:
        """
        Score how long to dwell on a channel based on observed AP density
        and packet rate.  Returns dwell_ms in [200, 2000].
        """
        state = (
            f"Channel {channel}. "
            f"APs visible: {ap_count}. "
            f"Packets/sec: {packet_rate:.1f}. "
            f"Target APs present: {len([b for b in target_bssids if b])}."
        )
        questions = {
            "dwell": {
                "type": "score",
                "description": "How long should the radio dwell on this channel?",
                "levels": [
                    {"label": "very_short", "description": "200ms - no targets, low traffic"},
                    {"label": "short",      "description": "400ms - some beacons, no targets"},
                    {"label": "medium",     "description": "700ms - moderate traffic"},
                    {"label": "long",       "description": "1200ms - high traffic or target present"},
                    {"label": "very_long",  "description": "2000ms - target AP active with clients"},
                ],
            }
        }
        dwell_map = {"very_short": 200, "short": 400, "medium": 700, "long": 1200, "very_long": 2000}
        result = await self._ask(state, questions)
        if result is None:
            dwell_ms = 700 if ap_count == 0 else min(200 + ap_count * 100, 2000)
            return ChannelDwellDecision(channel, dwell_ms, 0.0)
        score_label = result.get("dwell", {}).get("score", "medium")
        confidence  = result.get("dwell", {}).get("confidence", 0.0)
        return ChannelDwellDecision(channel, dwell_map.get(score_label, 700), confidence)

    # -- Decision 2: Deauth strategy selection --------------------------------

    async def deauth_strategy(
        self,
        ap_bssid: str,
        pmf_enabled: bool,
        wpa3: bool,
        client_count: int,
        prior_btm_successes: int,
        prior_csa_successes: int,
    ) -> DeauthStrategyDecision:
        """
        Choose the optimal deauth strategy for a specific AP based on its
        capabilities and our observed success history.
        """
        state = (
            f"AP {ap_bssid}. "
            f"PMF/802.11w: {'yes' if pmf_enabled else 'no'}. "
            f"WPA3: {'yes' if wpa3 else 'no'}. "
            f"Connected clients: {client_count}. "
            f"Prior BTM successes: {prior_btm_successes}. "
            f"Prior CSA successes: {prior_csa_successes}."
        )
        questions = {
            "strategy": {
                "type": "choice",
                "description": "Which deauth strategy is most likely to evict clients?",
                "options": [
                    {"value": "BTM_REQUEST",    "description": "802.11v BSS Transition Management Request - works even under PMF, requests client to roam"},
                    {"value": "CSA_INJECTION",  "description": "Channel Switch Announcement beacon injection - forces clients to vacate channel"},
                    {"value": "OCN_FLOOD",      "description": "Operating Channel Notification flood - destabilises channel state machine"},
                    {"value": "CLASSIC_DEAUTH", "description": "Classic deauth flood - blocked by PMF but fast when PMF is off"},
                ],
            }
        }
        result = await self._ask(state, questions)
        if result is None:
            fallback = "BTM_REQUEST" if pmf_enabled or wpa3 else "CLASSIC_DEAUTH"
            return DeauthStrategyDecision(fallback, 0.0, {})
        ans  = result.get("strategy", {})
        strat = ans.get("choice", "BTM_REQUEST" if pmf_enabled else "CLASSIC_DEAUTH")
        return DeauthStrategyDecision(
            strategy=strat,
            confidence=ans.get("confidence", 0.0),
            probabilities=ans.get("probabilities", {}),
        )

    # -- Decision 3: Crack priority scoring -----------------------------------

    async def crack_priority(
        self,
        ssid: str,
        encryption: str,
        client_count: int,
        signal_strength: int,
        has_wps: bool,
    ) -> CrackPriorityDecision:
        """
        Score how high-priority this AP's capture is for cracking (1=low, 5=high).
        Higher score = submit to cloud GPU first.
        """
        state = (
            f"AP SSID: '{ssid}'. Encryption: {encryption}. "
            f"Clients: {client_count}. Signal: {signal_strength} dBm. "
            f"WPS: {'enabled' if has_wps else 'disabled'}."
        )
        questions = {
            "priority": {
                "type": "score",
                "description": "How high priority is cracking this network?",
                "levels": [
                    {"label": "1", "description": "Low - open network or WEP already cracked"},
                    {"label": "2", "description": "Below average - weak signal, no clients"},
                    {"label": "3", "description": "Average - standard WPA2 target"},
                    {"label": "4", "description": "High - multiple clients, good signal, WPS enabled"},
                    {"label": "5", "description": "Critical - enterprise network, many clients, WPA3"},
                ],
            }
        }
        reason_map = {
            "1": "Low priority - minimal value",
            "2": "Below average - limited crack potential",
            "3": "Average priority - standard WPA2 target",
            "4": "High priority - active network with clients",
            "5": "Critical - high-value enterprise or heavily-used network",
        }
        result = await self._ask(state, questions)
        if result is None:
            score = min(5, max(1, client_count + (2 if has_wps else 0)))
            return CrackPriorityDecision(score, 0.0, reason_map.get(str(score), ""))
        ans   = result.get("priority", {})
        label = ans.get("score", "3")
        return CrackPriorityDecision(
            score=int(label) if label.isdigit() else 3,
            confidence=ans.get("confidence", 0.0),
            reason=reason_map.get(label, ""),
        )

    # -- Decision 4: EvilTwin portal template ---------------------------------

    async def portal_template(
        self,
        ap_bssid: str,
        vendor: str,
        wps_model: str,
        ssid: str,
    ) -> PortalTemplateDecision:
        """
        Choose the best vendor-cloning portal template to maximise
        credential submission probability.
        """
        state = (
            f"AP BSSID: {ap_bssid}. Detected vendor: '{vendor}'. "
            f"WPS model: '{wps_model}'. SSID: '{ssid}'."
        )
        questions = {
            "template": {
                "type": "choice",
                "description": "Which router vendor portal template best matches this AP?",
                "options": [
                    {"value": "tplink",  "description": "TP-Link Archer series - red theme"},
                    {"value": "netgear", "description": "NETGEAR Nighthawk/Orbi - purple theme"},
                    {"value": "asus",    "description": "ASUS RT/AX series - blue theme"},
                    {"value": "dlink",   "description": "D-Link DIR series - dark blue"},
                    {"value": "linksys", "description": "Linksys WRT series - light blue"},
                    {"value": "cisco",   "description": "Cisco/Meraki enterprise - corporate splash"},
                    {"value": "generic", "description": "Generic WiFi portal - fallback"},
                ],
            }
        }
        result = await self._ask(state, questions)
        if result is None:
            from wifit4.attacks.eviltwin.smart_portal import detect_vendor
            profile = detect_vendor(ap_bssid)
            return PortalTemplateDecision(profile.template_key or "generic", 0.0)
        ans = result.get("template", {})
        return PortalTemplateDecision(
            template_key=ans.get("choice", "generic"),
            confidence=ans.get("confidence", 0.0),
        )

    # -- Decision 5: WIDS active detection ------------------------------------

    async def wids_active(
        self,
        inject_failures: int,
        block_events: int,
        unusual_probe_responses: int,
        elapsed_since_last_success_s: float,
    ) -> WidsDetectionDecision:
        """
        Noul gate: estimate probability that a WIDS/WIPS is actively monitoring
        and blocking our injection attempts.
        """
        state = (
            f"Inject failures in last 30s: {inject_failures}. "
            f"Block/error events: {block_events}. "
            f"Unusual probe responses (potential honeypot): {unusual_probe_responses}. "
            f"Seconds since last successful inject: {elapsed_since_last_success_s:.0f}."
        )
        questions = {
            "wids": {
                "type": "noul",
                "description": "Is a WIDS/WIPS system actively detecting and blocking this audit?",
            }
        }
        result = await self._ask(state, questions)
        if result is None:
            prob = min(0.9, (inject_failures + block_events) * 0.15)
            return WidsDetectionDecision(prob > 0.5, prob)
        noul_val = result.get("wids", {})
        prob = noul_val if isinstance(noul_val, float) else noul_val.get("noul", 0.0)
        return WidsDetectionDecision(prob > 0.5, prob)

    # -- Decision 6: Network type classification ------------------------------

    async def network_type(
        self,
        ssid: str,
        auth_suite: str,
        has_radius_indicator: bool,
        beacon_vendor_ie: str,
        client_count: int,
    ) -> NetworkTypeDecision:
        """
        Classify whether the target is enterprise (802.1X), personal (PSK),
        open, or a hotspot - determines which attack campaign to launch.
        """
        state = (
            f"SSID: '{ssid}'. Auth suite: {auth_suite}. "
            f"RADIUS indicator in beacon: {'yes' if has_radius_indicator else 'no'}. "
            f"Vendor IE: '{beacon_vendor_ie}'. "
            f"Clients: {client_count}."
        )
        questions = {
            "type": {
                "type": "choice",
                "description": "What type of Wi-Fi network is this?",
                "options": [
                    {"value": "enterprise", "description": "WPA-Enterprise / 802.1X / RADIUS - requires username+password"},
                    {"value": "personal",   "description": "WPA2/WPA3-Personal / PSK - standard home/office"},
                    {"value": "open",       "description": "No encryption - open network"},
                    {"value": "hotspot",    "description": "Captive portal / commercial hotspot (hotel, café)"},
                ],
            }
        }
        result = await self._ask(state, questions)
        if result is None:
            ntype = "enterprise" if has_radius_indicator else "personal"
            return NetworkTypeDecision(ntype, 0.0, {})
        ans = result.get("type", {})
        return NetworkTypeDecision(
            network_type=ans.get("choice", "personal"),
            confidence=ans.get("confidence", 0.0),
            probabilities=ans.get("probabilities", {}),
        )

    # -- Core HTTP call -------------------------------------------------------

    async def _ask(
        self, state: str, questions: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not self._api_key:
            return None
        try:
            import httpx
            payload = {
                "model":     _JEV_MODEL,
                "state":     state,
                "questions": questions,
            }
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.post(
                    _JEV_API_URL,
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                resp.raise_for_status()
                self._call_count += 1
                return resp.json().get("answers", {})
        except Exception as exc:
            self._error_count += 1
            log.debug("Jev call failed (fallback to heuristics): %s", exc)
            return None

    # -- Stats ----------------------------------------------------------------

    @property
    def stats(self) -> dict:
        return {
            "calls":  self._call_count,
            "errors": self._error_count,
            "configured": self.is_configured(),
        }
