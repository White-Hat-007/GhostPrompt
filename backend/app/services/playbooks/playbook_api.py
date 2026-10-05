"""Playbook API — CRUD + execution endpoints."""


from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.logging import get_logger
from app.core.security import get_current_user
from app.services.playbooks.playbook_engine import playbook_engine

logger = get_logger("api.playbooks")
router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    trigger_type: str = "severity"
    trigger_conditions: dict = {}
    nodes: list = []
    edges: list = []


class PlaybookUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    trigger_type: str | None = None
    trigger_conditions: dict | None = None
    nodes: list | None = None
    edges: list | None = None
    status: str | None = None


@router.get("/")
async def list_playbooks(current_user: dict = Depends(get_current_user)):
    org_id = str(current_user.get("org_id", ""))
    return await playbook_engine.list_playbooks(org_id)


@router.post("/")
async def create_playbook(body: PlaybookCreate, current_user: dict = Depends(get_current_user)):
    org_id = str(current_user.get("org_id", ""))
    user_id = str(current_user.get("sub", ""))
    pb = await playbook_engine.create_playbook(body.model_dump(), org_id, user_id)
    return playbook_engine._serialize_playbook(pb)


@router.get("/{playbook_id}")
async def get_playbook(playbook_id: str, current_user: dict = Depends(get_current_user)):
    pb = await playbook_engine.get_playbook(playbook_id)
    if not pb:
        raise HTTPException(404, "Playbook not found")
    return pb


@router.put("/{playbook_id}")
async def update_playbook(playbook_id: str, body: PlaybookUpdate, current_user: dict = Depends(get_current_user)):
    pb = await playbook_engine.update_playbook(playbook_id, body.model_dump(exclude_unset=True))
    if not pb:
        raise HTTPException(404, "Playbook not found")
    return playbook_engine._serialize_playbook(pb)


@router.delete("/{playbook_id}")
async def delete_playbook(playbook_id: str, current_user: dict = Depends(get_current_user)):
    if not await playbook_engine.delete_playbook(playbook_id):
        raise HTTPException(404, "Playbook not found")
    return {"status": "deleted"}


@router.post("/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, current_user: dict = Depends(get_current_user)):
    """Manually trigger a playbook with a synthetic test event."""
    test_event = {
        "request_id": "manual-test",
        "action": "manual_trigger",
        "threat_level": "high",
        "threat_score": 0.85,
        "source_ip": "192.168.1.100",
        "model_provider": "test",
        "model_name": "test-model",
        "is_blocked": False,
        "detections": [],
        "threat_categories": ["test"],
    }
    try:
        execution = await playbook_engine.execute_playbook(playbook_id, test_event)
        return await playbook_engine.get_execution(execution.id)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/{playbook_id}/executions")
async def list_executions(playbook_id: str, current_user: dict = Depends(get_current_user)):
    return await playbook_engine.list_executions(playbook_id)


@router.get("/executions/{execution_id}")
async def get_execution(execution_id: str, current_user: dict = Depends(get_current_user)):
    ex = await playbook_engine.get_execution(execution_id)
    if not ex:
        raise HTTPException(404, "Execution not found")
    return ex
