"""
SOC Simulator - FastAPI Backend Entry Point.
Starts the log generation engine, WebSocket server, and REST API.
"""
import asyncio
import random
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func

from backend.database.connection import init_db, SessionLocal
from backend.database.seed import seed_database
from backend.models.log import Log
from backend.models.alert import Alert
from backend.websocket.manager import manager
from backend.correlation_engine.rules import CorrelationEngine
from backend.log_generators.windows import generate_windows_log
from backend.log_generators.linux import generate_linux_log
from backend.log_generators.network import generate_network_log
from backend.log_generators.email_gen import generate_email_log
from backend.log_generators.cloud import generate_cloud_log
from backend.api import auth, alerts, incidents, logs, simulations, mitre
from backend.utils.records import coerce_datetime_fields

# Correlation engine singleton
correlation_engine = CorrelationEngine()

# Background task flag
_running = False


async def log_generation_loop():
    """Background task that continuously generates fake telemetry."""
    global _running
    _running = True

    generators = [
        (generate_windows_log, 30),
        (generate_linux_log, 25),
        (generate_network_log, 25),
        (generate_email_log, 10),
        (generate_cloud_log, 10),
    ]
    gens, weights = zip(*generators)

    log_count = 0
    alert_count = 0

    while _running:
        try:
            # Generate 1-3 logs per cycle
            batch_size = random.randint(1, 3)
            db = SessionLocal()
            try:
                for _ in range(batch_size):
                    gen = random.choices(gens, weights=weights, k=1)[0]
                    log_data = gen()

                    # Store in database
                    log_entry = Log(**{k: v for k, v in coerce_datetime_fields(log_data).items() if hasattr(Log, k)})
                    db.add(log_entry)

                    # Broadcast via WebSocket
                    await manager.broadcast_log(log_data)
                    log_count += 1

                    # Run correlation engine
                    generated_alerts = correlation_engine.process_log(log_data)
                    for alert_data in generated_alerts:
                        alert_entry = Alert(**{k: v for k, v in coerce_datetime_fields(alert_data).items() if hasattr(Alert, k)})
                        db.add(alert_entry)
                        await manager.broadcast_alert(alert_data)
                        alert_count += 1

                db.commit()
            finally:
                db.close()

            # Broadcast dashboard stats periodically
            if log_count % 10 == 0:
                stats = _get_dashboard_stats()
                stats["eps"] = round(batch_size / max(0.5, random.uniform(0.5, 2.0)), 1)
                stats["total_logs"] = log_count
                stats["total_alerts"] = alert_count
                stats["ws_connections"] = manager.connection_count
                await manager.broadcast_stats(stats)

            # Random delay to simulate realistic log rates (0.3-1.5 seconds)
            await asyncio.sleep(random.uniform(0.3, 1.5))

        except Exception as e:
            print(f"[LOG_GEN] Error: {e}")
            await asyncio.sleep(2)


def _get_dashboard_stats() -> dict:
    """Get current dashboard statistics from the database."""
    db = SessionLocal()
    try:
        total_logs = db.query(func.count(Log.id)).scalar() or 0
        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
        active_alerts = db.query(func.count(Alert.id)).filter(Alert.status.in_(["new", "investigating"])).scalar() or 0
        critical_alerts = db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0

        severity_dist = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
        source_dist = dict(db.query(Log.source, func.count(Log.id)).group_by(Log.source).all())

        # Top attackers (source IPs with most malicious logs)
        top_attackers = db.query(
            Log.source_ip, func.count(Log.id)
        ).filter(Log.is_malicious >= 1, Log.source_ip.isnot(None)).group_by(
            Log.source_ip
        ).order_by(func.count(Log.id).desc()).limit(10).all()

        return {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "critical_alerts": critical_alerts,
            "severity_distribution": severity_dist,
            "source_distribution": source_dist,
            "top_attackers": [{"ip": ip, "count": cnt} for ip, cnt in top_attackers if ip],
        }
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle - init DB, seed, start log generation."""
    init_db()
    seed_database()
    task = asyncio.create_task(log_generation_loop())
    print("[SOC] Backend started - log generation active")
    yield
    global _running
    _running = False
    task.cancel()
    print("[SOC] Backend shutting down")


# FastAPI application
app = FastAPI(
    title="SOC Simulator",
    description="Security Operations Center Training Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(logs.router)
app.include_router(simulations.router)
app.include_router(mitre.router)


# WebSocket endpoints
@app.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket):
    await manager.connect(websocket, "logs")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "logs")


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await manager.connect(websocket, "alerts")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "alerts")


@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    await manager.connect(websocket, "dashboard")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "dashboard")


@app.websocket("/ws/incidents")
async def ws_incidents(websocket: WebSocket):
    await manager.connect(websocket, "incidents")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, "incidents")


# Health check
@app.get("/api/health")
def health():
    return {"status": "operational", "service": "SOC Simulator", "connections": manager.connection_count}


# Dashboard stats endpoint
@app.get("/api/dashboard/stats")
def dashboard_stats():
    return _get_dashboard_stats()
