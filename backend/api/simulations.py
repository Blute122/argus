"""Attack simulation API endpoints."""
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.models.attack_simulation import AttackSimulation
from backend.models.alert import Alert
from backend.models.log import Log
from backend.attack_simulator.campaigns import get_campaign, generate_campaign_stage_logs, list_campaigns
from backend.attack_simulator.scenarios import get_scenarios, get_scenario_detail, generate_simulation_logs
from backend.api.auth import get_current_user
from backend.utils.records import coerce_datetime_fields
from backend.api.auth import require_roles
from backend.websocket.manager import manager
from backend.correlation_engine.rules import CorrelationEngine

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
async def run_simulation(scenario_id: str, db: Session = Depends(get_db), _user=Depends(require_roles(['threat_hunter', 'admin']))):
    detail = get_scenario_detail(scenario_id)
    if not detail:
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

    logs = generate_simulation_logs(scenario_id, db)

    result = await _store_logs_and_alerts(logs, db)

    sim.status = "completed"
    sim.completed_at = datetime.now(timezone.utc)
    sim.generated_logs = result["logs_generated"]
    sim.generated_alerts = result["alerts_generated"]
    db.commit()

    return {
        "simulation_id": sim.id, "name": sim.name, "status": "completed",
        "logs_generated": result["logs_generated"], "alerts_generated": result["alerts_generated"],
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


@router.get("/campaigns")
def campaigns(_user=Depends(get_current_user)):
    return list_campaigns()


@router.get("/campaigns/runs")
def campaign_runs(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    runs = db.query(AttackSimulation).filter(AttackSimulation.attack_type == "campaign").order_by(AttackSimulation.created_at.desc()).limit(50).all()
    return [_format_campaign_run(run) for run in runs]


@router.get("/campaigns/runs/{run_id}")
def campaign_run_detail(run_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    run = _get_campaign_run(run_id, db)
    return _format_campaign_run(run)


@router.post("/campaigns/start/{campaign_id}")
def start_campaign(campaign_id: str, db: Session = Depends(get_db), _user=Depends(require_roles(['threat_hunter', 'admin']))):
    campaign = get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    config = {
        "campaign_id": campaign_id,
        "current_stage": -1,
        "total_stages": len(campaign["stages"]),
        "stages": [
            {
                **stage,
                "index": index,
                "status": "pending",
                "logs_generated": 0,
                "alerts_generated": 0,
                "detected": False,
                "executed_at": None,
            }
            for index, stage in enumerate(campaign["stages"])
        ],
        "target_assets": campaign["target_assets"],
    }
    run = AttackSimulation(
        name=campaign["name"],
        description=campaign["description"],
        attack_type="campaign",
        mitre_tactic="Multiple",
        mitre_technique="Multiple",
        mitre_technique_name="Staged Campaign",
        status="running",
        started_at=datetime.now(timezone.utc),
        scenario_config=json.dumps(config),
        results_summary=json.dumps({"coverage": 0, "detections": 0, "missed": len(campaign["stages"])}),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return _format_campaign_run(run)


@router.post("/campaigns/runs/{run_id}/next")
async def run_next_campaign_stage(run_id: int, db: Session = Depends(get_db), _user=Depends(require_roles(['threat_hunter', 'admin']))):
    run = _get_campaign_run(run_id, db)
    result = await _execute_next_stage(run, db)
    return result


@router.post("/campaigns/runs/{run_id}/autorun")
async def autorun_campaign(run_id: int, db: Session = Depends(get_db), _user=Depends(require_roles(['threat_hunter', 'admin']))):
    run = _get_campaign_run(run_id, db)
    results = []
    while run.status != "completed":
        results.append(await _execute_next_stage(run, db))
        db.refresh(run)
    return {"run": _format_campaign_run(run), "stages_executed": len(results)}


async def _execute_next_stage(run: AttackSimulation, db: Session):
    config = _json_obj(run.scenario_config)
    campaign_id = config.get("campaign_id")
    next_index = int(config.get("current_stage", -1)) + 1
    stages = config.get("stages", [])
    if next_index >= len(stages):
        run.status = "completed"
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
        return _format_campaign_run(run)

    logs = generate_campaign_stage_logs(campaign_id, next_index, db)
    result = await _store_logs_and_alerts(logs, db)
    stage = stages[next_index]
    stage["status"] = "completed"
    stage["logs_generated"] = result["logs_generated"]
    stage["alerts_generated"] = result["alerts_generated"]
    stage["detected"] = result["alerts_generated"] > 0
    stage["executed_at"] = datetime.now(timezone.utc).isoformat()
    config["current_stage"] = next_index
    config["stages"] = stages

    detections = sum(1 for item in stages if item.get("detected"))
    completed = sum(1 for item in stages if item.get("status") == "completed")
    coverage = round((detections / completed) * 100, 1) if completed else 0
    run.generated_logs = (run.generated_logs or 0) + result["logs_generated"]
    run.generated_alerts = (run.generated_alerts or 0) + result["alerts_generated"]
    run.scenario_config = json.dumps(config)
    run.results_summary = json.dumps({
        "coverage": coverage,
        "detections": detections,
        "missed": completed - detections,
        "completed_stages": completed,
        "total_stages": len(stages),
    })
    if completed >= len(stages):
        run.status = "completed"
        run.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(run)
    return _format_campaign_run(run)


async def _store_logs_and_alerts(logs: list[dict], db: Session):
    engine = CorrelationEngine()
    alerts_generated = 0
    for log_data in logs:
        log_entry = Log(**{k: v for k, v in coerce_datetime_fields(log_data).items() if hasattr(Log, k)})
        db.add(log_entry)
        await manager.broadcast_log(log_data)
        for alert_data in engine.process_log(log_data):
            alert_entry = Alert(**{k: v for k, v in coerce_datetime_fields(alert_data).items() if hasattr(Alert, k)})
            db.add(alert_entry)
            await manager.broadcast_alert(alert_data)
            alerts_generated += 1
    db.flush()
    return {"logs_generated": len(logs), "alerts_generated": alerts_generated}


def _get_campaign_run(run_id: int, db: Session):
    run = db.query(AttackSimulation).filter(AttackSimulation.id == run_id, AttackSimulation.attack_type == "campaign").first()
    if not run:
        raise HTTPException(status_code=404, detail="Campaign run not found")
    return run


def _format_campaign_run(run: AttackSimulation):
    config = _json_obj(run.scenario_config)
    summary = _json_obj(run.results_summary)
    stages = config.get("stages", [])
    return {
        "id": run.id,
        "name": run.name,
        "description": run.description,
        "status": run.status,
        "campaign_id": config.get("campaign_id"),
        "current_stage": config.get("current_stage", -1),
        "total_stages": config.get("total_stages", len(stages)),
        "target_assets": config.get("target_assets", []),
        "stages": stages,
        "generated_logs": run.generated_logs or 0,
        "generated_alerts": run.generated_alerts or 0,
        "coverage": summary.get("coverage", 0),
        "detections": summary.get("detections", 0),
        "missed": summary.get("missed", 0),
        "started_at": str(run.started_at) if run.started_at else None,
        "completed_at": str(run.completed_at) if run.completed_at else None,
        "created_at": str(run.created_at),
    }


def _json_obj(value):
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}
