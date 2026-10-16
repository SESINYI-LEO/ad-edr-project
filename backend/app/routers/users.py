from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import admin_only, current_user
from app.models import ADUser, Role, SystemUser
from app.routers.common import ad_user_out, user_out
from app.schemas import UserCreate
from app.security import hash_secret
from app.services import audit

router = APIRouter(prefix="/api", tags=["users"])


@router.get("/users")
def list_users(user=Depends(current_user), db: Session = Depends(get_db)):
    return [user_out(u) for u in db.scalars(select(SystemUser).order_by(SystemUser.username))]


@router.post("/users")
def create_user(body: UserCreate, admin=Depends(admin_only), db: Session = Depends(get_db)):
    if db.scalar(select(SystemUser).where(SystemUser.username == body.username)):
        raise HTTPException(409, "Username already exists")
    u = SystemUser(username=body.username, email=body.email, hashed_password=hash_secret(body.password), role=Role(body.role))
    db.add(u)
    audit.log(db, admin, "user_created", details=f"{body.username} ({body.role})")
    db.commit()
    return user_out(u)


@router.get("/ad/users")
def ad_users(user=Depends(current_user), db: Session = Depends(get_db)):
    return [ad_user_out(u) for u in db.scalars(select(ADUser).order_by(ADUser.username))]
