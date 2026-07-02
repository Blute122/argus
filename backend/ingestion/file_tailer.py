"""Polling file tailer.

Follows a set of files and feeds newly-appended lines into the pipeline. Uses
simple offset polling (no OS-specific watch APIs) so it works identically on
Windows, Linux and macOS. Handles truncation/rotation by resetting the offset
when a file shrinks.
"""

import asyncio
import os

from backend.config import settings
from backend.ingestion.parsers import parse as parse_raw
from backend.ingestion.pipeline import ingest_event

_POLL_SECONDS = 1.0


class FileTailer:
    def __init__(self):
        self._task = None
        self._stop = asyncio.Event()
        self._offsets: dict[str, int] = {}

    async def start(self):
        paths = settings.file_tail_path_list()
        # Start at end-of-file so we only ingest new lines, not the whole backlog.
        for path in paths:
            try:
                self._offsets[path] = os.path.getsize(path)
            except OSError:
                self._offsets[path] = 0
        self._task = asyncio.create_task(self._run(paths))
        print(f"[SOC] File tailer following {len(paths)} path(s)")

    async def _run(self, paths):
        source_type = settings.file_tail_source_type
        tenant = settings.default_tenant
        while not self._stop.is_set():
            for path in paths:
                await self._read_new(path, source_type, tenant)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_POLL_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def _read_new(self, path, source_type, tenant):
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        offset = self._offsets.get(path, 0)
        if size < offset:  # rotated/truncated
            offset = 0
        if size == offset:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                lines = fh.readlines()
                self._offsets[path] = fh.tell()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parsed = parse_raw(line, source_type=source_type)
            if parsed:
                parsed.setdefault("source", "file")
                await ingest_event(parsed, ingest_source="file", tenant_id=tenant)

    async def stop(self):
        self._stop.set()
        if self._task:
            await self._task
