"""
Phase 3 - Hashcat cloud webhook + in-app async cracker.

Two independent subsystems:

  CloudCrackUploader   - fires an httpx async POST whenever a new .hc22000
                         capture is validated, targeting a user-configured
                         webhook (private GPU server, vast.ai, etc.).
                         Polls for a result and fires on_result when cracked.

  InAppCracker         - for small/medium wordlists: runs hashcat as a local
                         subprocess entirely within wifit4, streams stdout,
                         and reports the plaintext PSK through on_result.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

log = logging.getLogger("wifit4.crack.cloud")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CrackJob:
    ssid: str
    bssid: str
    hc22000_path: Path
    pcap_path: Path | None = None


@dataclass
class CrackResult:
    job: CrackJob
    psk: str
    source: str  # "local" | "cloud"


# ---------------------------------------------------------------------------
# Cloud webhook uploader
# ---------------------------------------------------------------------------

class CloudCrackUploader:
    """
    Async uploader.  Requires httpx (added to project deps).

    Webhook contract (server-side, user-operated):
      POST /upload  multipart: file=<hc22000>, ssid=<str>, bssid=<str>
        → 200 {"job_id": "<id>"}
      GET  /result/<job_id>
        → 200 {"status": "pending"|"cracked"|"failed", "psk": "<str or null>"}
    """

    def __init__(
        self,
        webhook_url: str,
        on_result: Callable[[CrackResult], None],
        poll_interval: float = 15.0,
        max_polls: int = 240,       # 240 × 15 s = 1 hour max wait
        api_key: str = "",
    ) -> None:
        self._webhook_url = webhook_url.rstrip("/")
        self._on_result = on_result
        self._poll_interval = poll_interval
        self._max_polls = max_polls
        self._api_key = api_key
        self._active_jobs: dict[str, CrackJob] = {}

    async def submit(self, job: CrackJob) -> None:
        try:
            import httpx
        except ImportError:
            log.error("httpx not installed - pip install httpx")
            return

        headers = {"X-API-Key": self._api_key} if self._api_key else {}
        async with httpx.AsyncClient(timeout=30) as client:
            with open(job.hc22000_path, "rb") as fh:
                files = {"file": (job.hc22000_path.name, fh, "application/octet-stream")}
                data  = {"ssid": job.ssid, "bssid": job.bssid}
                try:
                    resp = await client.post(
                        f"{self._webhook_url}/upload",
                        files=files,
                        data=data,
                        headers=headers,
                    )
                    resp.raise_for_status()
                    job_id = resp.json()["job_id"]
                    log.info("Cloud crack job submitted: %s (job_id=%s)", job.ssid, job_id)
                    self._active_jobs[job_id] = job
                    asyncio.create_task(self._poll(job_id, job, headers))
                except Exception as exc:
                    log.warning("Cloud upload failed for %s: %s", job.ssid, exc)

    async def _poll(
        self,
        job_id: str,
        job: CrackJob,
        headers: dict,
    ) -> None:
        try:
            import httpx
        except ImportError:
            return

        async with httpx.AsyncClient(timeout=15) as client:
            for _ in range(self._max_polls):
                await asyncio.sleep(self._poll_interval)
                try:
                    resp = await client.get(
                        f"{self._webhook_url}/result/{job_id}",
                        headers=headers,
                    )
                    resp.raise_for_status()
                    body = resp.json()
                except Exception as exc:
                    log.debug("Poll error for job %s: %s", job_id, exc)
                    continue

                status = body.get("status", "pending")
                if status == "cracked":
                    psk = body.get("psk", "")
                    log.info("Cloud crack SUCCESS %s → %s", job.ssid, psk)
                    self._on_result(CrackResult(job=job, psk=psk, source="cloud"))
                    self._active_jobs.pop(job_id, None)
                    return
                if status == "failed":
                    log.info("Cloud crack FAILED for %s", job.ssid)
                    self._active_jobs.pop(job_id, None)
                    return

        log.warning("Cloud crack timed out for job %s", job_id)
        self._active_jobs.pop(job_id, None)


# ---------------------------------------------------------------------------
# In-app local hashcat runner
# ---------------------------------------------------------------------------

class InAppCracker:
    """
    Runs hashcat locally as a subprocess for WPA/WPA2 (-m 22000) and
    WPA-PMKID-only (-m 22001) captures.

    Streams stdout line-by-line; fires on_result the moment hashcat reports
    a cracked hash in "TOKEN:PLAINTEXT" format.
    """

    HASHCAT_MODES = {
        "wpa2": 22000,
        "pmkid": 22001,
        "netntlmv2": 5500,
    }

    def __init__(
        self,
        on_result: Callable[[CrackResult], None],
        hashcat_bin: str = "hashcat",
        workdir: Path | None = None,
    ) -> None:
        self._on_result = on_result
        self._hashcat_bin = hashcat_bin
        self._workdir = workdir or Path(tempfile.mkdtemp(prefix="wifit4_crack_"))
        self._running_procs: list[asyncio.subprocess.Process] = []

    def hashcat_available(self) -> bool:
        return shutil.which(self._hashcat_bin) is not None

    async def crack(
        self,
        job: CrackJob,
        wordlist: Path,
        mode: str = "wpa2",
        rules: list[str] | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        if not self.hashcat_available():
            log.error("hashcat not found in PATH - skipping local crack")
            return

        hash_mode = self.HASHCAT_MODES.get(mode, 22000)
        potfile   = self._workdir / f"{job.bssid.replace(':', '')}.pot"

        cmd = [
            self._hashcat_bin,
            "-m", str(hash_mode),
            "-a", "0",              # dictionary attack
            "--status",
            "--status-timer", "5",
            "--potfile-path", str(potfile),
            "--quiet",
            str(job.hc22000_path),
            str(wordlist),
        ]
        if rules:
            for rule in rules:
                cmd += ["-r", rule]
        if extra_args:
            cmd += extra_args

        log.info("Starting local crack: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self._workdir),
        )
        self._running_procs.append(proc)

        try:
            await self._stream_output(proc, job)
        finally:
            self._running_procs.remove(proc)

        # Check potfile for result even if stdout missed it
        if potfile.exists():
            for line in potfile.read_text(errors="replace").splitlines():
                if ":" in line:
                    psk = line.split(":")[-1].strip()
                    if psk:
                        self._on_result(CrackResult(job=job, psk=psk, source="local"))
                        return

    async def _stream_output(
        self,
        proc: asyncio.subprocess.Process,
        job: CrackJob,
    ) -> None:
        assert proc.stdout
        async for raw_line in proc.stdout:
            line = raw_line.decode(errors="replace").strip()
            # hashcat prints "HASH:PLAINTEXT" when cracked
            if line and not line.startswith("[") and ":" in line:
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and parts[1]:
                    psk = parts[1].strip()
                    log.info("LOCAL crack SUCCESS %s → %s", job.ssid, psk)
                    self._on_result(CrackResult(job=job, psk=psk, source="local"))
                    proc.terminate()
                    return

    def stop_all(self) -> None:
        for proc in self._running_procs:
            try:
                proc.terminate()
            except Exception:
                pass
