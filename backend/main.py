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

from backend.config import settings
from backend.database.connection import init_db, SessionLocal
from backend.database.seed import seed_database
from backend.models.alert import Alert
from backend.models.asset import Asset
from backend.websocket.manager import manager
from backend.log_generators.windows import generate_windows_log
from backend.log_generators.linux import generate_linux_log
from backend.log_generators.network import generate_network_log
from backend.log_generators.email_gen import generate_email_log
from backend.log_generators.cloud import generate_cloud_log
from backend.api import auth, alerts, incidents, logs, simulations, mitre, assets, reports, rules, audit as audit_api
from backend.detection.engine import detection_engine
from backend.detection.scheduler import scheduler as detection_scheduler
from backend.ingestion import http_ingest
from backend.ingestion.pipeline import ingest_event
from backend.search import get_log_store

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
            # Generate 1-3 logs per cycle, routed through the shared pipeline
            # (normalize -> store -> detect -> broadcast), same path as real
            # ingestion sources.
            batch_size = random.randint(1, 3)
            for _ in range(batch_size):
                gen = random.choices(gens, weights=weights, k=1)[0]
                result = await ingest_event(gen(), ingest_source="demo")
                log_count += 1
                alert_count += result["alerts"]

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
    """Assemble dashboard stats: log metrics from the log store, alert/asset
    metrics from the relational metadata DB."""
    log_stats = get_log_store().dashboard_log_stats()
    db = SessionLocal()
    try:
        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
        active_alerts = db.query(func.count(Alert.id)).filter(Alert.status.in_(["new", "investigating"])).scalar() or 0
        critical_alerts = db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0

        severity_dist = dict(db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
        total_assets = db.query(func.count(Asset.id)).scalar() or 0
        high_risk_assets = db.query(func.count(Asset.id)).filter(Asset.risk_score >= 70).scalar() or 0

        return {
            "total_logs": log_stats["total_logs"],
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "critical_alerts": critical_alerts,
            "severity_distribution": severity_dist,
            "source_distribution": log_stats["source_distribution"],
            "total_assets": total_assets,
            "high_risk_assets": high_risk_assets,
            "top_attackers": log_stats["top_attackers"],
        }
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle - init DB, seed, bootstrap search, start ingestion."""
    init_db()
    seed_database()

    if settings.jwt_secret_is_default():
        print("[SOC] WARNING: JWT_SECRET is the built-in default. Set JWT_SECRET "
              "in the environment before exposing this service.")

    if settings.opensearch_enabled:
        from backend.search.client import bootstrap_indices, ping
        if ping():
            bootstrap_indices()
            print("[SOC] OpenSearch connected - log store ready")
        else:
            print("[SOC] WARNING: OPENSEARCH_ENABLED but OpenSearch is unreachable")

    if settings.ingest_enabled:
        from backend.ingestion.bootstrap import ensure_default_ingest_key
        ensure_default_ingest_key()

    # Load detection rules and start the scheduled (threshold) runner.
    detection_engine.load()
    await detection_scheduler.start()

    # Real ingestion listeners (opt-in via config).
    syslog_listeners = None
    file_tailer = None
    if settings.syslog_enabled:
        from backend.ingestion.syslog_server import SyslogListeners
        syslog_listeners = SyslogListeners()
        await syslog_listeners.start()
    if settings.file_tail_enabled and settings.file_tail_path_list():
        from backend.ingestion.file_tailer import FileTailer
        file_tailer = FileTailer()
        await file_tailer.start()

    task = None
    if settings.demo_mode:
        task = asyncio.create_task(log_generation_loop())
        print("[SOC] Backend started - demo log generation active")
    else:
        print("[SOC] Backend started - DEMO_MODE off (awaiting real ingestion)")

    yield

    global _running
    _running = False
    if task:
        task.cancel()
    await detection_scheduler.stop()
    if syslog_listeners:
        await syslog_listeners.stop()
    if file_tailer:
        await file_tailer.stop()
    print("[SOC] Backend shutting down")


# FastAPI application
app = FastAPI(
    title="SOC Simulator",
    description="Security Operations Center Training Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for frontend
# Wildcard origins and credentialed requests are mutually exclusive per the CORS
# spec; only allow credentials when specific origins are configured.
_cors_origins = settings.cors_origin_list()
_allow_credentials = _cors_origins != ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_allow_credentials,
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
app.include_router(assets.router)
app.include_router(reports.router)
app.include_router(rules.router)
app.include_router(audit_api.router)
if settings.ingest_enabled:
    app.include_router(http_ingest.router)


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
