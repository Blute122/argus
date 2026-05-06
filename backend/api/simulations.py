"""Attack simulation API endpoints."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.models.attack_simulation import AttackSimulation
from backend.attack_simulator.scenarios import get_scenarios, get_scenario_detail, generate_simulation_logs
from backend.api.auth import get_current_user
from backend.utils.records import coerce_datetime_fields

router = APIRouter(prefix="/api/simulations", tags=["Attack Simulations"])


@router.get("/scenarios")
def list_scenarios(_user=Depends(get_current_user)):
    return get_scenarios()


@router.get("/scenarios/{scenario_id}")
def scenario_detail(scenario_id: str, _user=Depends(get_current_user)):
    detail = get_scenario_detail(scenario_id)
    if not detail:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scenario not found")
    return detail


@router.post("/run/{scenario_id}")
async def run_simulation(scenario_id: str, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    detail = get_scenario_detail(scenario_id)
    if not detail:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scenario not found")

    sim = AttackSimulation(
        name=detail["name"], description=detail["description"],
        attack_type=detail["attack_type"], mitre_tactic=detail["mitre_tactic"],
        mitre_technique=detail["mitre_technique"], mitre_technique_name=detail["mitre_technique_name"],
        status="running", started_at=datetime.now(timezone.utc),
    )
    db.add(sim)
    db.commit()
    db.refresh(sim)

    logs = generate_simulation_logs(scenario_id)

    # Store logs and broadcast them
    from backend.models.log import Log
    from backend.websocket.manager import manager
    from backend.correlation_engine.rules import CorrelationEngine

    engine = CorrelationEngine()
    alerts_generated = 0

    for log_data in logs:
        log_entry = Log(**{k: v for k, v in coerce_datetime_fields(log_data).items() if hasattr(Log, k)})
        db.add(log_entry)
        await manager.broadcast_log(log_data)
        # Run correlation
        alerts = engine.process_log(log_data)
        for alert_data in alerts:
            from backend.models.alert import Alert
            alert_entry = Alert(**{k: v for k, v in coerce_datetime_fields(alert_data).items() if hasattr(Alert, k)})
            db.add(alert_entry)
            await manager.broadcast_alert(alert_data)
            alerts_generated += 1

    sim.status = "completed"
    sim.completed_at = datetime.now(timezone.utc)
    sim.generated_logs = len(logs)
    sim.generated_alerts = alerts_generated
    db.commit()

    return {
        "simulation_id": sim.id, "name": sim.name, "status": "completed",
        "logs_generated": len(logs), "alerts_generated": alerts_generated,
    }


@router.get("/history")
def simulation_history(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    sims = db.query(AttackSimulation).order_by(AttackSimulation.created_at.desc()).limit(50).all()
    return [{
        "id": s.id, "name": s.name, "attack_type": s.attack_type,
        "status": s.status, "mitre_technique": s.mitre_technique,
        "generated_logs": s.generated_logs, "generated_alerts": s.generated_alerts,
        "created_at": str(s.created_at),
    } for s in sims]
