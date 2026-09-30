"""
Async multi-stage RX pipeline.

Stages:
  USB I/O thread  →  RingBuffer  →  FrameParser (async)  →  Sink callbacks

The USB thread writes raw bulk-transfer bytes into RingBuffer slots without
touching any Python objects beyond the bytearray view.  The async stage runs
in the event loop and calls registered sink callbacks with parsed frames - the
same interface that wifit4.wlan.sink already expects.

Usage::

    pipeline = RxPipeline(ring_buffer, frame_parser)
    pipeline.add_sink(my_callback)
    asyncio.create_task(pipeline.run())

    # USB I/O thread:
    pipeline.ingest_raw(raw_usb_bytes)
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from .ring_buffer import RingBuffer


class RxPipeline:
    def __init__(
        self,
        ring_buffer: RingBuffer,
        frame_parser: Callable[[bytes], Any | None],
    ) -> None:
        self._ring = ring_buffer
        self._parse = frame_parser
        self._sinks: list[Callable[[Any], None]] = []
        self._running = False
        self._stats = _PipelineStats()
        self._loop: asyncio.AbstractEventLoop | None = None

    def add_sink(self, callback: Callable[[Any], None]) -> None:
        self._sinks.append(callback)

    def remove_sink(self, callback: Callable[[Any], None]) -> None:
        self._sinks.remove(callback)

    # -- USB I/O thread entry point -------------------------------------------

    def ingest_raw(self, data: bytes | bytearray) -> None:
        """Non-blocking; called from any thread (USB I/O, timer, test harness)."""
        self._ring.write_frame(data)
        self._stats.rx_bytes += len(data)
        self._stats.rx_frames += 1
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._wake)

    def _wake(self) -> None:
        pass  # nudge event loop; queue already populated

    # -- async pipeline -------------------------------------------------------

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._running = True
        queue = self._ring.queue
        while self._running:
            try:
                raw_bytes, length = await asyncio.wait_for(queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            await self._dispatch(raw_bytes, length)

    async def _dispatch(self, slot_id: int, length: int) -> None:
        # In the write_frame path slot_id carries raw bytes reference; length is real
        # For production use, callers pass actual bytes via ingest_raw which queues them
        # Parse in thread pool to avoid blocking event loop on heavy frames
        t0 = time.monotonic()
        try:
            frame = await asyncio.get_event_loop().run_in_executor(
                None, self._parse_safe, slot_id, length
            )
        except Exception:
            self._stats.parse_errors += 1
            return
        if frame is None:
            return
        self._stats.parse_ns += int((time.monotonic() - t0) * 1e9)
        self._stats.parsed_frames += 1
        for sink in self._sinks:
            try:
                sink(frame)
            except Exception:
                pass

    def _parse_safe(self, slot_id: int, length: int) -> Any | None:
        # slot_id in the simplified path is just the opaque id; real bytes come via queue
        # This is called from run_in_executor - no event loop here
        try:
            return self._parse(slot_id)  # type: ignore[arg-type]
        except Exception:
            return None

    def stop(self) -> None:
        self._running = False

    @property
    def stats(self) -> "_PipelineStats":
        return self._stats


class _PipelineStats:
    __slots__ = ("rx_bytes", "rx_frames", "parsed_frames", "parse_errors", "parse_ns")

    def __init__(self) -> None:
        self.rx_bytes = 0
        self.rx_frames = 0
        self.parsed_frames = 0
        self.parse_errors = 0
        self.parse_ns = 0

    def __repr__(self) -> str:
        avg_us = (self.parse_ns / max(self.parsed_frames, 1)) / 1000
        return (
            f"rx={self.rx_frames} parsed={self.parsed_frames} "
            f"errors={self.parse_errors} avg_parse={avg_us:.1f}µs"
        )
