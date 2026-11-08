from sqlalchemy.orm import Session

from app.models import AuditEntry


def log(db: Session, user, action: str, outcome: str = "success", details: str = "", ip: str | None = None, commit: bool = False):
    db.add(AuditEntry(
        user_id=getattr(user, "id", None), username=getattr(user, "username", None),
        action=action, outcome=outcome, details=details[:2000], ip_address=ip,
    ))
    if commit:
        db.commit()
