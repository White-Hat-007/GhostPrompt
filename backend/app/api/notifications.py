"""
User Notifications API

Endpoints for the in-app notification system:
- GET  /notifications        — fetch unread/all notifications for current user
- POST /notifications/{id}/read    — mark as read
- POST /notifications/{id}/dismiss — dismiss notification
- GET  /notifications/unread-count — badge count for the bell icon
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, desc

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.notification import UserNotification

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("")
async def list_notifications(
    unread_only: bool = Query(False, description="Only return unread notifications"),
    limit: int = Query(20, le=50),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get notifications for the current user."""
    user_id = current_user.get("user_id")
    if not user_id:
        raise HTTPException(401, "Authentication required")

    query = (
        select(UserNotification)
        .where(
            UserNotification.user_id == user_id,
            UserNotification.dismissed == False,
        )
        .order_by(desc(UserNotification.created_at))
        .limit(limit)
    )

    if unread_only:
        query = query.where(UserNotification.is_read == False)

    result = await db.execute(query)
    notifications = result.scalars().all()

    return {
        "notifications": [
            {
                "id": str(n.id),
                "title": n.title,
                "message": n.message,
                "severity": n.severity,
                "category": n.category,
                "is_read": n.is_read,
                "created_at": n.created_at.isoformat() if n.created_at else None,
                "read_at": n.read_at.isoformat() if n.read_at else None,
            }
            for n in notifications
        ],
        "count": len(notifications),
    }


@router.get("/unread-count")
async def unread_count(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the unread notification count (for the bell badge)."""
    user_id = current_user.get("user_id")
    if not user_id:
        raise HTTPException(401, "Authentication required")

    result = await db.execute(
        select(func.count(UserNotification.id)).where(
            UserNotification.user_id == user_id,
            UserNotification.is_read == False,
            UserNotification.dismissed == False,
        )
    )
    count = result.scalar() or 0
    return {"unread_count": count}


@router.post("/{notification_id}/read")
async def mark_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark a notification as read."""
    user_id = current_user.get("user_id")
    result = await db.execute(
        select(UserNotification).where(
            UserNotification.id == notification_id,
            UserNotification.user_id == user_id,
        )
    )
    notif = result.scalar_one_or_none()
    if not notif:
        raise HTTPException(404, "Notification not found")

    notif.is_read = True
    notif.read_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "read"}


@router.post("/{notification_id}/dismiss")
async def dismiss_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Dismiss a notification (hide from UI permanently)."""
    user_id = current_user.get("user_id")
    result = await db.execute(
        select(UserNotification).where(
            UserNotification.id == notification_id,
            UserNotification.user_id == user_id,
        )
    )
    notif = result.scalar_one_or_none()
    if not notif:
        raise HTTPException(404, "Notification not found")

    notif.dismissed = True
    notif.is_read = True
    notif.read_at = notif.read_at or datetime.now(timezone.utc)
    await db.commit()
    return {"status": "dismissed"}


# ── Helper for creating notifications from backend code ──

async def notify_user(
    db: AsyncSession,
    user_id,
    title: str,
    message: str,
    severity: str = "warning",
    category: str = "system",
    organization_id=None,
):
    """
    Create an in-app notification for a user.
    
    Call this from any backend code that needs to alert a user
    about a change that affects them (role changes, permission
    downgrades, security events, etc).
    """
    notif = UserNotification(
        user_id=user_id,
        organization_id=organization_id,
        title=title,
        message=message,
        severity=severity,
        category=category,
    )
    db.add(notif)
    # Don't commit here — let the caller manage the transaction
    return notif
