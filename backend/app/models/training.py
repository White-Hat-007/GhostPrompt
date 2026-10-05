from sqlalchemy import Column, String, Float, Integer, JSON, DateTime
from datetime import datetime, timezone

from app.core.database import Base

class TrainingJobModel(Base):
    __tablename__ = "training_jobs"

    id = Column(String, primary_key=True, index=True)
    org_id = Column(String, index=True)
    model_type = Column(String)
    base_model = Column(String)
    dataset_path = Column(String)
    status = Column(String)
    progress = Column(Float, default=0.0)
    current_epoch = Column(Integer, default=0)
    total_epochs = Column(Integer, default=5)
    metrics = Column(JSON, default=dict)
    output_dir = Column(String, nullable=True)
    error = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
