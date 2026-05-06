"""Authentication API endpoints - login, register, session management."""
from datetime import datetime, timedelta, timezone
import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from pydantic import BaseModel
from backend.database.connection import get_db
from backend.models.user import User, UserRole
from backend.security import hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

SECRET_KEY = os.getenv("SOC_SIMULATOR_SECRET_KEY", "soc-simulator-dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: str
    role: str = "analyst_l1"


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    token = create_access_token({"sub": user.username, "role": user.role.value if isinstance(user.role, UserRole) else user.role})
    return Token(
        access_token=token, token_type="bearer",
        user=UserResponse(id=user.id, username=user.username, email=user.email,
                          full_name=user.full_name, role=user.role.value if isinstance(user.role, UserRole) else user.role,
                          is_active=user.is_active)
    )


@router.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    user = User(
        username=user_data.username, email=user_data.email,
        password_hash=hash_password(user_data.password),
        full_name=user_data.full_name, role=UserRole(user_data.role),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserResponse(id=user.id, username=user.username, email=user.email,
                        full_name=user.full_name, role=user.role.value, is_active=user.is_active)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(id=current_user.id, username=current_user.username,
                        email=current_user.email, full_name=current_user.full_name,
                        role=current_user.role.value if isinstance(current_user.role, UserRole) else current_user.role,
                        is_active=current_user.is_active)


@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    users = db.query(User).all()
    return [UserResponse(id=u.id, username=u.username, email=u.email, full_name=u.full_name,
                         role=u.role.value if isinstance(u.role, UserRole) else u.role, is_active=u.is_active) for u in users]
