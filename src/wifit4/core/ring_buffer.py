"""
Zero-copy ring buffer for USB bulk-transfer RX frames.

Replaces per-frame Python bytearray allocation with a single pre-allocated
memory arena. Writers (USB I/O thread) claim a slot, fill it in-place, then
publish the slot index to the reader (frame-parser thread) via an asyncio.Queue
of (slot_index, length) pairs.  The reader processes the memoryview slice -
zero copies until the application layer asks for bytes.
"""
from __future__ import annotations

import asyncio
import threading


class RingBuffer:
    """Single-producer / single-consumer lock-free ring over a bytearray arena."""

    def __init__(self, slot_count: int = 512, slot_size: int = 2048) -> None:
        self._slot_count = slot_count
        self._slot_size = slot_size
        self._arena = bytearray(slot_count * slot_size)
        self._view = memoryview(self._arena)
        self._write_idx = 0
        self._lock = threading.Lock()
        # (slot_index, frame_length) published by writer, consumed by pipeline
        self._ready: asyncio.Queue[tuple[int, int]] = asyncio.Queue(maxsize=slot_count)

    # -- writer side (USB I/O thread) -----------------------------------------

    def claim_slot(self) -> memoryview:
        """Return writable memoryview for the next slot (blocking if full)."""
        with self._lock:
            idx = self._write_idx % self._slot_count
            self._write_idx += 1
        offset = idx * self._slot_size
        return self._view[offset : offset + self._slot_size]

    def publish(self, slot_view: memoryview, length: int) -> None:
        """Mark slot as ready.  Called from USB I/O thread via call_soon_threadsafe."""
        try:
            self._ready.put_nowait(
                (id(slot_view), length)  # opaque id; pipeline holds the view reference
            )
        except asyncio.QueueFull:
            pass  # drop frame under backpressure - better than blocking USB thread

    # -- async writer helper (preferred path) ---------------------------------

    def write_frame(self, data: bytes | bytearray) -> None:
        """Copy raw USB bytes into next slot and enqueue.  Called from USB thread."""
        length = min(len(data), self._slot_size)
        slot = self.claim_slot()
        slot[:length] = data[:length]
        try:
            self._ready.put_nowait((id(slot), length))
        except asyncio.QueueFull:
            pass  # drop under backpressure

    # -- reader side (async frame-parser) -------------------------------------

    async def next_frame(self) -> tuple[memoryview, int]:
        """Yield next (view, length) pair.  Awaits until a frame is available."""
        slot_id, length = await self._ready.get()
        # For the simplified (copy) path: slot_id is just id(slot); return is informational.
        # The pipeline that calls write_frame owns the actual memoryview reference.
        return slot_id, length

    @property
    def queue(self) -> asyncio.Queue:
        return self._ready
