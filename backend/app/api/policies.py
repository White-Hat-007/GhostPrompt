"""
Policy Management Routes

CRUD operations for security policies and rules.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.permissions import require_permission
from app.core.security import get_current_user
from app.models.policy import Policy, PolicyRule
from app.schemas.schemas import PolicyCreate, PolicyResponse, PolicyUpdate

router = APIRouter(prefix="/policies", tags=["Policies"], dependencies=[Depends(require_permission("policies.manage"))])


@router.get("", response_model=list[PolicyResponse])
async def list_policies(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all policies for the organization."""
    org_id = current_user["org_id"]
    result = await db.execute(
        select(Policy)
        .where(Policy.organization_id == org_id)
        .options(selectinload(Policy.rules))
        .order_by(Policy.priority.desc())
    )
    return result.scalars().all()


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_data: PolicyCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new security policy."""
    org_id = current_user["org_id"]

    policy = Policy(
        organization_id=org_id,
        name=policy_data.name,
        description=policy_data.description,
        policy_type=policy_data.policy_type,
        applies_to=policy_data.applies_to,
        priority=policy_data.priority,
    )
    db.add(policy)
    await db.flush()

    for rule_data in policy_data.rules:
        rule = PolicyRule(
            policy_id=policy.id,
            name=rule_data.name,
            description=rule_data.description,
            rule_type=rule_data.rule_type,
            detector=rule_data.detector,
            threshold=rule_data.threshold,
            parameters=rule_data.parameters,
            action=rule_data.action,
            severity=rule_data.severity,
            is_active=rule_data.is_active,
            priority=rule_data.priority,
        )
        db.add(rule)

    # Reload with relationships
    await db.flush()
    result = await db.execute(
        select(Policy)
        .where(Policy.id == policy.id)
        .options(selectinload(Policy.rules))
    )
    return result.scalar_one()


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific policy by ID."""
    org_id = current_user["org_id"]
    result = await db.execute(
        select(Policy)
        .where(Policy.id == policy_id, Policy.organization_id == org_id)
        .options(selectinload(Policy.rules))
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: UUID,
    policy_update: PolicyUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update an existing policy and its rules."""
    org_id = current_user["org_id"]
    result = await db.execute(
        select(Policy)
        .where(Policy.id == policy_id, Policy.organization_id == org_id)
        .options(selectinload(Policy.rules))
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    # Update base fields
    update_data = policy_update.model_dump(exclude_unset=True)
    if "rules" in update_data:
        del update_data["rules"]
    for key, value in update_data.items():
        setattr(policy, key, value)

    # Recreate rules if provided
    if policy_update.rules is not None:
        # Delete old rules
        for rule in policy.rules:
            await db.delete(rule)
        
        # Add new rules
        for rule_data in policy_update.rules:
            rule = PolicyRule(
                policy_id=policy.id,
                name=rule_data.name,
                description=rule_data.description,
                rule_type=rule_data.rule_type,
                detector=rule_data.detector,
                threshold=rule_data.threshold,
                parameters=rule_data.parameters,
                action=rule_data.action,
                severity=rule_data.severity,
                is_active=rule_data.is_active,
                priority=rule_data.priority,
            )
            db.add(rule)

    await db.commit()
    
    # Reload
    result = await db.execute(
        select(Policy)
        .where(Policy.id == policy_id)
        .options(selectinload(Policy.rules))
    )
    return result.scalar_one()


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a policy."""
    org_id = current_user["org_id"]
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id, Policy.organization_id == org_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if policy.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete default policy")
    await db.delete(policy)


@router.patch("/{policy_id}/toggle")
async def toggle_policy(
    policy_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggle a policy's active status."""
    org_id = current_user["org_id"]
    result = await db.execute(
        select(Policy).where(Policy.id == policy_id, Policy.organization_id == org_id)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.is_active = not policy.is_active
    return {"id": str(policy.id), "is_active": policy.is_active}
