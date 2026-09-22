from sqlalchemy.orm import Session
from . import models


def log_action(
    db: Session,
    user_id: int,
    action: str,
    target_type: str | None = None,
    target_id: int | None = None,
    details: str | None = None
):
    entry = models.AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details
    )
    db.add(entry)
    db.commit()