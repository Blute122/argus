"""Scheduled detection runner.

Periodically evaluates threshold rules against the log store and emits alerts
through the same path as streaming detections. A short-lived dedup cache stops a
rule from re-alerting on the same group every tick while the window still holds
the triggering events.
"""

import asyncio
import time

from backend.config import settings
from backend.detection.engine import detection_engine
from backend.models.alert import Alert
from backend.database.connection import SessionLocal
from backend.search import get_log_store
from backend.utils.records import coerce_datetime_fields
from backend.websocket.manager import manager

_INTERVAL_SECONDS = 30


class DetectionScheduler:
    def __init__(self):
        self._task = None
        self._stop = asyncio.Event()
        self._recent: dict[str, float] = {}  # dedup key -> last fired epoch

    async def start(self):
        self._task = asyncio.create_task(self._run())
        print(f"[DETECT] Scheduler started (every {_INTERVAL_SECONDS}s)")

    async def _run(self):
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception as exc:
                print(f"[DETECT] Scheduler error: {exc}")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def _tick(self):
        store = get_log_store()
        now = time.time()
        self._prune(now)
        for rule in detection_engine.active_threshold_rules():
            alerts = rule.evaluate(store)
            fresh = []
            for alert in alerts:
                # Dedup within roughly two windows so we don't re-fire each tick.
                key = f"{rule.id}:{alert.get('source_ip') or alert.get('hostname') or '_'}"
                if now - self._recent.get(key, 0) < rule.window_minutes * 60:
                    continue
                self._recent[key] = now
                fresh.append(alert)
            if fresh:
                await self._emit(fresh)
                detection_engine.record_fires([rule.id], increment=len(fresh))

    async def _emit(self, alerts):
        db = SessionLocal()
        try:
            for alert_data in alerts:
                entry = Alert(**{k: v for k, v in coerce_datetime_fields(alert_data).items() if hasattr(Alert, k)})
                db.add(entry)
                await manager.broadcast_alert(alert_data)
            db.commit()
        finally:
            db.close()

    def _prune(self, now):
        stale = [k for k, ts in self._recent.items() if now - ts > 3600]
        for key in stale:
            self._recent.pop(key, None)

    async def stop(self):
        self._stop.set()
        if self._task:
            await self._task


scheduler = DetectionScheduler()
