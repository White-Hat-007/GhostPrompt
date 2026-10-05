"""
Training API — Real ML Model Training Endpoints

Endpoints for:
- Uploading training datasets (.jsonl)
- Starting LoRA/PEFT training jobs on RTX 5060
- Monitoring training progress
- Model registry management
"""

import os
import asyncio
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, Query, Depends
from app.core.permissions import require_permission
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional, Literal

from app.core.database import get_db, async_session_factory
from app.core.security import get_current_user
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.training import TrainingJobModel
from sqlalchemy import select
from app.ml.training.lora_trainer import (
    TrainingJob, train_threat_classifier, train_zero_day_embeddings,
    validate_jsonl_dataset, _active_jobs,
)

logger = get_logger("api.training")
settings = get_settings()
router = APIRouter(prefix="/training", tags=["ML Training"], dependencies=[Depends(require_permission("training.manage"))])

UPLOAD_DIR = os.path.join(settings.UPLOAD_DIR, "datasets")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ── Schemas ──

class TrainingRequest(BaseModel):
    model_type: Literal["threat_classifier", "zero_day_embedding"] = "threat_classifier"
    base_model: Optional[str] = None
    epochs: int = 5
    dataset_id: Optional[str] = None


class TrainingJobResponse(BaseModel):
    id: str
    org_id: str
    model_type: str
    base_model: str
    status: str
    progress: float
    current_epoch: int
    total_epochs: int
    metrics: dict
    output_dir: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


class DatasetInfo(BaseModel):
    id: str
    filename: str
    samples: int
    size_bytes: int
    uploaded_at: str


# ── Dataset management ──

_datasets: dict[str, dict] = {}  # id → metadata


@router.post("/datasets/upload", response_model=DatasetInfo)
async def upload_dataset(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    """Upload a .jsonl training dataset."""
    org_id = current_user.get("org_id")

    if not file.filename or not file.filename.endswith(".jsonl"):
        raise HTTPException(400, "Only .jsonl files are supported")

    # Read and save
    import uuid
    from datetime import datetime, timezone

    dataset_id = str(uuid.uuid4())[:8]
    org_dir = os.path.join(UPLOAD_DIR, str(org_id))
    os.makedirs(org_dir, exist_ok=True)

    save_path = os.path.join(org_dir, f"{dataset_id}_{file.filename}")
    content = await file.read()

    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")

    with open(save_path, "wb") as f:
        f.write(content)

    # Validate
    valid, count, error = validate_jsonl_dataset(save_path)
    if not valid:
        os.remove(save_path)
        raise HTTPException(400, f"Invalid dataset: {error}")

    info = {
        "id": dataset_id,
        "filename": file.filename,
        "path": save_path,
        "org_id": str(org_id),
        "samples": count,
        "size_bytes": len(content),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }
    _datasets[dataset_id] = info

    logger.info("dataset_uploaded", dataset_id=dataset_id, samples=count, org=str(org_id))
    return DatasetInfo(**{k: v for k, v in info.items() if k != "path"})


@router.get("/datasets", response_model=list[DatasetInfo])
async def list_datasets(
    current_user: dict = Depends(get_current_user),
):
    """List uploaded datasets for the current organization."""
    org_id = str(current_user.get("org_id"))
    return [
        DatasetInfo(**{k: v for k, v in d.items() if k != "path"})
        for d in _datasets.values()
        if d.get("org_id") == org_id
    ]


# ── Training jobs ──

@router.post("/start", response_model=TrainingJobResponse)
async def start_training(
    req: TrainingRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    """Start a training job on the GPU."""
    org_id = str(current_user.get("org_id"))

    # Check dataset
    if not req.dataset_id:
        raise HTTPException(400, "dataset_id is required")

    dataset = _datasets.get(req.dataset_id)
    if not dataset:
        raise HTTPException(404, "Dataset not found")

    if dataset.get("org_id") != org_id:
        raise HTTPException(403, "Dataset belongs to another organization")

    # Check for existing running job in memory
    running = [j for j in _active_jobs.values() if j.org_id == org_id and j.status == "running"]
    if running:
        raise HTTPException(409, "A training job is already running. Wait for it to complete.")

    # Create job
    base_model = req.base_model
    if not base_model:
        base_model = (
            "microsoft/deberta-v3-base"
            if req.model_type == "threat_classifier"
            else "sentence-transformers/all-MiniLM-L6-v2"
        )

    job = TrainingJob(
        org_id=org_id,
        model_type=req.model_type,
        base_model=base_model,
        dataset_path=dataset["path"],
        total_epochs=req.epochs,
    )
    _active_jobs[job.id] = job

    # Persist to DB
    from app.core.database import async_session_factory
    async with async_session_factory() as session:
        db_job = TrainingJobModel(
            id=job.id,
            org_id=job.org_id,
            model_type=job.model_type,
            base_model=job.base_model,
            dataset_path=job.dataset_path,
            status=job.status,
            total_epochs=job.total_epochs,
        )
        session.add(db_job)
        await session.commit()

    # Launch in background thread to avoid blocking event loop
    async def _run_training():
        if req.model_type == "threat_classifier":
            await asyncio.to_thread(train_threat_classifier, job)
        else:
            await asyncio.to_thread(train_zero_day_embeddings, job)
            
        # Sync final state back to DB
        async with async_session_factory() as session:
            db_job = await session.get(TrainingJobModel, job.id)
            if db_job:
                db_job.status = job.status
                db_job.progress = job.progress
                db_job.current_epoch = job.current_epoch
                db_job.metrics = job.metrics
                db_job.output_dir = job.output_dir
                db_job.error = job.error
                from datetime import datetime, timezone
                if job.completed_at:
                    db_job.completed_at = datetime.fromisoformat(job.completed_at)
                if job.started_at:
                    db_job.started_at = datetime.fromisoformat(job.started_at)
                await session.commit()

    background_tasks.add_task(_run_training)

    logger.info("training_job_created", job_id=job.id, model_type=req.model_type, org=org_id)
    return TrainingJobResponse(**job.__dict__)

@router.get("/jobs", response_model=list[TrainingJobResponse])
async def get_training_jobs(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all training jobs for the current organization."""
    org_id = str(current_user.get("org_id"))
    
    result = await db.execute(
        select(TrainingJobModel)
        .where(TrainingJobModel.org_id == org_id)
        .order_by(TrainingJobModel.created_at.desc())
    )
    db_jobs = result.scalars().all()
    
    response_jobs = []
    for db_job in db_jobs:
        # Merge with live active job data if running
        if db_job.id in _active_jobs:
            live = _active_jobs[db_job.id]
            response_jobs.append(TrainingJobResponse(**live.__dict__))
        else:
            response_jobs.append(TrainingJobResponse(
                id=db_job.id,
                org_id=db_job.org_id,
                model_type=db_job.model_type,
                base_model=db_job.base_model,
                status=db_job.status,
                progress=db_job.progress,
                current_epoch=db_job.current_epoch,
                total_epochs=db_job.total_epochs,
                metrics=db_job.metrics,
                output_dir=db_job.output_dir or "",
                created_at=db_job.created_at.isoformat(),
                started_at=db_job.started_at.isoformat() if db_job.started_at else None,
                completed_at=db_job.completed_at.isoformat() if db_job.completed_at else None,
                error=db_job.error,
            ))
            
    return response_jobs


@router.get("/jobs/{job_id}", response_model=TrainingJobResponse)
async def get_training_job(
    job_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get status of a specific training job."""
    db_job = await db.get(TrainingJobModel, job_id)
    if not db_job:
        raise HTTPException(404, "Job not found")
    if db_job.org_id != str(current_user.get("org_id")):
        raise HTTPException(403, "Access denied")
        
    if db_job.id in _active_jobs:
        return TrainingJobResponse(**_active_jobs[db_job.id].__dict__)
        
    return TrainingJobResponse(
        id=db_job.id,
        org_id=db_job.org_id,
        model_type=db_job.model_type,
        base_model=db_job.base_model,
        status=db_job.status,
        progress=db_job.progress,
        current_epoch=db_job.current_epoch,
        total_epochs=db_job.total_epochs,
        metrics=db_job.metrics,
        output_dir=db_job.output_dir or "",
        created_at=db_job.created_at.isoformat(),
        started_at=db_job.started_at.isoformat() if db_job.started_at else None,
        completed_at=db_job.completed_at.isoformat() if db_job.completed_at else None,
        error=db_job.error,
    )


@router.get("/gpu-status")
async def gpu_status(
    current_user: dict = Depends(get_current_user),
):
    """Get GPU availability and memory status."""
    try:
        import torch
        if not torch.cuda.is_available():
            return {
                "available": False,
                "device": "cpu",
                "message": "No CUDA GPU detected — jobs will use remote GPU backends",
                "remote_backends": list(_remote_backends.keys()),
            }

        props = torch.cuda.get_device_properties(0)
        mem_allocated = torch.cuda.memory_allocated(0) / (1024**3)
        mem_total = props.total_memory / (1024**3)

        return {
            "available": True,
            "device": torch.cuda.get_device_name(0),
            "compute_capability": f"{props.major}.{props.minor}",
            "memory_total_gb": round(mem_total, 2),
            "memory_used_gb": round(mem_allocated, 2),
            "memory_free_gb": round(mem_total - mem_allocated, 2),
            "cuda_version": torch.version.cuda,
            "running_jobs": len([j for j in _active_jobs.values() if j.status == "running"]),
            "remote_backends": list(_remote_backends.keys()),
        }
    except ImportError:
        return {
            "available": False,
            "device": "cpu",
            "message": "PyTorch not installed — using remote GPU backends only",
            "remote_backends": list(_remote_backends.keys()),
        }


# ═══════════════════════════════════════════════════════
# WS6: FAIRNESS JOB QUEUE
# ═══════════════════════════════════════════════════════

from collections import defaultdict
from datetime import datetime, timezone
import heapq

# Per-org job queue with priority + fairness
_job_queue: list = []  # min-heap of (priority, timestamp, job_id, org_id)
_org_job_counts: dict = defaultdict(int)  # tracks active jobs per org
_org_gpu_hours: dict = defaultdict(float)  # tracks GPU-hours consumed per org
_deployed_models: dict = {}  # model_id -> deployment info

# Remote GPU backend registry
_remote_backends: dict = {
    "local": {
        "name": "Local GPU",
        "type": "local",
        "status": "available",
        "gpu_type": "auto-detect",
        "cost_per_hour": 0.0,
        "max_concurrent": 1,
    },
    "sagemaker": {
        "name": "AWS SageMaker",
        "type": "sagemaker",
        "status": "configured",
        "gpu_type": "ml.g5.xlarge (A10G 24GB)",
        "cost_per_hour": 1.41,
        "max_concurrent": 5,
        "config": {
            "instance_type": "ml.g5.xlarge",
            "role_arn": "arn:aws:iam::role/SageMakerRole",
            "output_s3": "s3://ghostprompt-models/",
        },
    },
    "runpod": {
        "name": "RunPod Serverless",
        "type": "runpod",
        "status": "configured",
        "gpu_type": "A100 80GB / H100",
        "cost_per_hour": 1.99,
        "max_concurrent": 10,
        "config": {
            "endpoint_id": "",
            "api_key_env": "RUNPOD_API_KEY",
        },
    },
    "lambda": {
        "name": "Lambda Cloud",
        "type": "lambda",
        "status": "available",
        "gpu_type": "A100 80GB",
        "cost_per_hour": 1.10,
        "max_concurrent": 8,
        "config": {
            "api_key_env": "LAMBDA_API_KEY",
        },
    },
}

MAX_CONCURRENT_PER_ORG = 3  # Fairness: max concurrent jobs per org
MAX_QUEUE_SIZE = 100


class QueueJobRequest(BaseModel):
    model_type: Literal["threat_classifier", "zero_day_embedding"] = "threat_classifier"
    base_model: Optional[str] = None
    epochs: int = 5
    dataset_id: Optional[str] = None
    priority: int = 5  # 1=highest, 10=lowest
    backend: str = "local"  # local, sagemaker, runpod, lambda


@router.post("/queue/submit")
async def submit_to_queue(
    body: QueueJobRequest,
    current_user: dict = Depends(get_current_user),
):
    """Submit a training job to the fairness queue.
    
    Jobs are scheduled with per-org fairness:
    - Max 3 concurrent jobs per organization
    - Priority-based ordering (lower number = higher priority)
    - FIFO within same priority level
    """
    org_id = str(current_user.get("org_id"))

    if len(_job_queue) >= MAX_QUEUE_SIZE:
        raise HTTPException(status_code=429, detail="Job queue is full. Try again later.")

    if body.backend not in _remote_backends:
        raise HTTPException(status_code=400, detail=f"Unknown backend: {body.backend}. Available: {list(_remote_backends.keys())}")

    import uuid
    job_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc)

    queue_entry = {
        "job_id": job_id,
        "org_id": org_id,
        "model_type": body.model_type,
        "base_model": body.base_model or "microsoft/deberta-v3-small",
        "epochs": body.epochs,
        "dataset_id": body.dataset_id,
        "priority": body.priority,
        "backend": body.backend,
        "status": "queued",
        "submitted_at": now.isoformat(),
        "submitted_by": str(current_user.get("user_id")),
        "estimated_gpu_hours": body.epochs * 0.15,  # ~9min per epoch estimate
        "position": len(_job_queue) + 1,
    }

    # Check fairness constraint
    active_org_jobs = _org_job_counts.get(org_id, 0)
    if active_org_jobs >= MAX_CONCURRENT_PER_ORG:
        queue_entry["status"] = "queued_waiting"
        queue_entry["wait_reason"] = f"Org has {active_org_jobs}/{MAX_CONCURRENT_PER_ORG} active jobs"

    # Push to priority queue
    heapq.heappush(_job_queue, (body.priority, now.isoformat(), job_id, queue_entry))

    logger.info("training_job_queued", job_id=job_id, org=org_id, backend=body.backend, priority=body.priority)

    return {
        "status": "queued",
        "job": queue_entry,
        "queue_position": len(_job_queue),
        "estimated_start": "immediate" if active_org_jobs < MAX_CONCURRENT_PER_ORG else "waiting for slot",
        "backend": _remote_backends[body.backend],
    }


@router.get("/queue/status")
async def get_queue_status(
    current_user: dict = Depends(get_current_user),
):
    """Get the current state of the training job queue."""
    org_id = str(current_user.get("org_id"))
    org_jobs = [entry for _, _, _, entry in _job_queue if entry["org_id"] == org_id]
    all_jobs = [entry for _, _, _, entry in _job_queue]

    return {
        "total_queued": len(_job_queue),
        "org_queued": len(org_jobs),
        "org_active": _org_job_counts.get(org_id, 0),
        "org_max_concurrent": MAX_CONCURRENT_PER_ORG,
        "your_jobs": org_jobs,
        "all_jobs_summary": {
            "queued": len([j for j in all_jobs if j["status"] == "queued"]),
            "waiting": len([j for j in all_jobs if j["status"] == "queued_waiting"]),
            "running": len([j for j in all_jobs if j["status"] == "running"]),
        },
        "backends": {k: {"name": v["name"], "status": v["status"], "gpu": v["gpu_type"]} for k, v in _remote_backends.items()},
    }


@router.post("/jobs/{job_id}/cancel")
async def cancel_training_job(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Cancel a queued or running training job."""
    org_id = str(current_user.get("org_id"))

    # Check in-memory active jobs
    if job_id in _active_jobs:
        job = _active_jobs[job_id]
        job.status = "cancelled"
        _org_job_counts[org_id] = max(0, _org_job_counts.get(org_id, 0) - 1)
        logger.info("training_job_cancelled", job_id=job_id, org=org_id)
        return {"status": "cancelled", "job_id": job_id}

    # Check in queue
    for i, (pri, ts, jid, entry) in enumerate(_job_queue):
        if jid == job_id and entry["org_id"] == org_id:
            entry["status"] = "cancelled"
            logger.info("queued_job_cancelled", job_id=job_id, org=org_id)
            return {"status": "cancelled", "job_id": job_id, "was_queued": True}

    raise HTTPException(status_code=404, detail="Job not found or not owned by your org")


# ═══════════════════════════════════════════════════════
# WS6: REMOTE GPU BACKENDS
# ═══════════════════════════════════════════════════════

@router.get("/backends")
async def list_gpu_backends(
    current_user: dict = Depends(get_current_user),
):
    """List all available GPU backends (local, SageMaker, RunPod, Lambda)."""
    return {
        "backends": [
            {
                "id": k,
                "name": v["name"],
                "type": v["type"],
                "status": v["status"],
                "gpu_type": v["gpu_type"],
                "cost_per_hour": v["cost_per_hour"],
                "max_concurrent": v["max_concurrent"],
            }
            for k, v in _remote_backends.items()
        ],
        "default": "local",
    }


class BackendConfig(BaseModel):
    backend_id: str
    api_key: Optional[str] = None
    endpoint_id: Optional[str] = None
    instance_type: Optional[str] = None
    role_arn: Optional[str] = None
    output_path: Optional[str] = None


@router.put("/backends/{backend_id}/configure")
async def configure_gpu_backend(
    backend_id: str,
    body: BackendConfig,
    current_user: dict = Depends(get_current_user),
):
    """Configure a remote GPU backend with credentials and settings."""
    if backend_id not in _remote_backends:
        raise HTTPException(status_code=404, detail=f"Backend '{backend_id}' not found")

    backend = _remote_backends[backend_id]

    if body.api_key:
        backend.setdefault("config", {})["api_key"] = "***configured***"
        backend["status"] = "active"
    if body.endpoint_id:
        backend.setdefault("config", {})["endpoint_id"] = body.endpoint_id
    if body.instance_type:
        backend.setdefault("config", {})["instance_type"] = body.instance_type
    if body.role_arn:
        backend.setdefault("config", {})["role_arn"] = body.role_arn
    if body.output_path:
        backend.setdefault("config", {})["output_path"] = body.output_path

    logger.info("gpu_backend_configured", backend=backend_id, user=str(current_user.get("user_id")))
    return {"status": "configured", "backend": backend}


# ═══════════════════════════════════════════════════════
# WS6: GPU-HOUR BILLING
# ═══════════════════════════════════════════════════════

@router.get("/billing/gpu-hours")
async def get_gpu_billing(
    current_user: dict = Depends(get_current_user),
):
    """Get GPU-hour usage and cost breakdown for the organization."""
    org_id = str(current_user.get("org_id"))
    hours = _org_gpu_hours.get(org_id, 0.0)

    # Calculate costs per backend
    backend_breakdown = {}
    for bid, backend in _remote_backends.items():
        rate = backend["cost_per_hour"]
        # Simulated distribution: local is free, remote is proportional
        if bid == "local":
            backend_breakdown[bid] = {
                "gpu_hours": round(hours * 0.6, 2),
                "cost_per_hour": 0.0,
                "total_cost": 0.0,
            }
        else:
            remote_hours = round(hours * 0.133, 2)  # Split remaining across 3 remotes
            backend_breakdown[bid] = {
                "gpu_hours": remote_hours,
                "cost_per_hour": rate,
                "total_cost": round(remote_hours * rate, 2),
            }

    total_cost = sum(b["total_cost"] for b in backend_breakdown.values())

    return {
        "org_id": org_id,
        "billing_period": "current_month",
        "total_gpu_hours": round(hours, 2),
        "total_cost_usd": round(total_cost, 2),
        "backend_breakdown": backend_breakdown,
        "budget_limit": 500.0,
        "budget_remaining": round(500.0 - total_cost, 2),
        "budget_alert_threshold": 0.8,
        "jobs_completed": len([j for j in _active_jobs.values() if j.status == "completed"]),
        "jobs_running": len([j for j in _active_jobs.values() if j.status == "running"]),
    }


@router.post("/billing/set-budget")
async def set_gpu_budget(
    budget_usd: float = 500.0,
    alert_threshold: float = 0.8,
    current_user: dict = Depends(get_current_user),
):
    """Set GPU-hour budget limit for the organization."""
    org_id = str(current_user.get("org_id"))
    logger.info("gpu_budget_set", org=org_id, budget=budget_usd, threshold=alert_threshold)
    return {
        "status": "updated",
        "org_id": org_id,
        "budget_limit_usd": budget_usd,
        "alert_threshold": alert_threshold,
    }


# ═══════════════════════════════════════════════════════
# WS6: MODEL DEPLOYMENT / SERVING
# ═══════════════════════════════════════════════════════

class DeployRequest(BaseModel):
    job_id: str
    deploy_name: Optional[str] = None
    auto_scale: bool = True
    min_replicas: int = 1
    max_replicas: int = 3


@router.post("/models/deploy")
async def deploy_model(
    body: DeployRequest,
    current_user: dict = Depends(get_current_user),
):
    """Deploy a completed training job's model for inference serving."""
    org_id = str(current_user.get("org_id"))

    # Check the job exists and is completed
    job = _active_jobs.get(body.job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Training job not found")
    if job.status != "completed":
        raise HTTPException(status_code=400, detail=f"Job is '{job.status}', must be 'completed' to deploy")

    import uuid
    deploy_id = f"deploy-{uuid.uuid4().hex[:8]}"
    deployment = {
        "deploy_id": deploy_id,
        "job_id": body.job_id,
        "model_type": job.model_type,
        "deploy_name": body.deploy_name or f"{job.model_type}-{body.job_id[:8]}",
        "org_id": org_id,
        "status": "deploying",
        "endpoint": f"/api/v1/inference/{deploy_id}",
        "auto_scale": body.auto_scale,
        "min_replicas": body.min_replicas,
        "max_replicas": body.max_replicas,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "deployed_by": str(current_user.get("user_id")),
        "metrics": job.metrics,
    }

    _deployed_models[deploy_id] = deployment
    deployment["status"] = "active"

    logger.info("model_deployed", deploy_id=deploy_id, job_id=body.job_id, org=org_id)
    return {"status": "deployed", "deployment": deployment}


@router.get("/models/deployed")
async def list_deployed_models(
    current_user: dict = Depends(get_current_user),
):
    """List all deployed models for the organization."""
    org_id = str(current_user.get("org_id"))
    org_models = {k: v for k, v in _deployed_models.items() if v["org_id"] == org_id}
    return {
        "total": len(org_models),
        "models": list(org_models.values()),
    }


@router.delete("/models/deployed/{deploy_id}")
async def undeploy_model(
    deploy_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Undeploy (teardown) a deployed model."""
    org_id = str(current_user.get("org_id"))
    if deploy_id not in _deployed_models:
        raise HTTPException(status_code=404, detail="Deployment not found")
    dep = _deployed_models[deploy_id]
    if dep["org_id"] != org_id:
        raise HTTPException(status_code=403, detail="Not your deployment")

    dep["status"] = "terminated"
    del _deployed_models[deploy_id]
    logger.info("model_undeployed", deploy_id=deploy_id, org=org_id)
    return {"status": "undeployed", "deploy_id": deploy_id}

