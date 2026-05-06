"""
WebSocket connection manager for real-time event streaming.
Broadcasts logs, alerts, and dashboard stats to connected clients.
"""
import json
import asyncio
from fastapi import WebSocket
from typing import Dict, Set


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events."""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "logs": set(),
            "alerts": set(),
            "dashboard": set(),
            "incidents": set(),
        }

    async def connect(self, websocket: WebSocket, channel: str = "logs"):
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = set()
        self.active_connections[channel].add(websocket)

    def disconnect(self, websocket: WebSocket, channel: str = "logs"):
        if channel in self.active_connections:
            self.active_connections[channel].discard(websocket)

    async def broadcast(self, channel: str, data: dict):
        """Broadcast data to all connections on a channel."""
        if channel not in self.active_connections:
            return
        dead = set()
        for ws in self.active_connections[channel]:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active_connections[channel].discard(ws)

    async def broadcast_log(self, log_data: dict):
        await self.broadcast("logs", {"type": "log", "data": log_data})

    async def broadcast_alert(self, alert_data: dict):
        await self.broadcast("alerts", {"type": "alert", "data": alert_data})
        await self.broadcast("dashboard", {"type": "alert", "data": alert_data})

    async def broadcast_stats(self, stats: dict):
        await self.broadcast("dashboard", {"type": "stats", "data": stats})

    async def broadcast_incident(self, incident_data: dict):
        await self.broadcast("incidents", {"type": "incident", "data": incident_data})

    @property
    def connection_count(self) -> int:
        return sum(len(conns) for conns in self.active_connections.values())


# Singleton instance
manager = ConnectionManager()
