"""Authentication API endpoints - login, session management, MFA, users."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from pydantic import BaseModel

from backend import audit, mfa
from backend.config import settings
from backend.database.connection import get_db
from backend.models.user import User, UserRole
from backend.ratelimit import rate_limiter
from backend.security import hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

SECRET_KEY = settings.jwt_secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.jwt_expire_minutes

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

_login_rate = rate_limiter("login", settings.login_rate_limit, settings.login_rate_window_seconds)


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
    mfa_enabled: bool = False

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class MfaCode(BaseModel):
    code: str


def _role_str(user: User) -> str:
    return user.role.value if isinstance(user.role, UserRole) else user.role


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


def require_roles(allowed_roles: list[str]):
    def role_checker(current_user: User = Depends(get_current_user)):
        user_role = _role_str(current_user)
        # Admin always has bypass access.
        if user_role not in allowed_roles and user_role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required roles: {', '.join(allowed_roles)}",
            )
        return current_user
    return role_checker


def _user_response(user: User) -> UserResponse:
    return UserResponse(id=user.id, username=user.username, email=user.email,
                        full_name=user.full_name, role=_role_str(user),
                        is_active=user.is_active, mfa_enabled=bool(user.mfa_enabled))


@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(),
          otp: str = Form(default=None), db: Session = Depends(get_db), _rl=Depends(_login_rate)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        audit.record("login.failure", actor_username=form_data.username, request=request,
                     outcome="failure", detail="bad credentials", db=db)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.mfa_enabled:
        if not otp or not mfa.verify(user.mfa_secret, otp):
            audit.record("login.mfa_failure", actor=user, request=request, outcome="failure", db=db)
            raise HTTPException(status_code=401, detail="MFA code required or invalid")

    user.last_login = datetime.now(timezone.utc)
    db.commit()
    audit.record("login.success", actor=user, request=request, db=db)
    token = create_access_token({"sub": user.username, "role": _role_str(user)})
    return Token(access_token=token, token_type="bearer", user=_user_response(user))


@router.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, request: Request, db: Session = Depends(get_db),
             admin: User = Depends(require_roles(["admin"]))):
    """Create a user. Admin-only (no public self-registration)."""
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    try:
        role = UserRole(user_data.role)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")
    user = User(
        username=user_data.username, email=user_data.email,
        password_hash=hash_password(user_data.password),
        full_name=user_data.full_name, role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record("user.create", actor=admin, target_type="user", target_id=user.id,
                 detail=f"role={role.value}", request=request, db=db)
    return _user_response(user)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return _user_response(current_user)


@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_roles(["admin"]))):
    return [_user_response(u) for u in db.query(User).all()]


# --- MFA (TOTP) --------------------------------------------------------------

@router.post("/mfa/enroll")
def mfa_enroll(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate a TOTP secret; returns the otpauth URI to render as a QR code.
    MFA is not active until confirmed via /mfa/activate."""
    secret = mfa.generate_secret()
    current_user.mfa_secret = secret
    db.commit()
    return {"secret": secret, "otpauth_uri": mfa.provisioning_uri(secret, current_user.username)}


@router.post("/mfa/activate", response_model=UserResponse)
def mfa_activate(data: MfaCode, request: Request,
                 current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.mfa_secret or not mfa.verify(current_user.mfa_secret, data.code):
        raise HTTPException(status_code=400, detail="Invalid code; enroll and try again")
    current_user.mfa_enabled = True
    db.commit()
    audit.record("mfa.enable", actor=current_user, request=request, db=db)
    return _user_response(current_user)


@router.post("/mfa/disable", response_model=UserResponse)
def mfa_disable(data: MfaCode, request: Request,
                current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.mfa_enabled:
        return _user_response(current_user)
    if not mfa.verify(current_user.mfa_secret, data.code):
        raise HTTPException(status_code=400, detail="Invalid code")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    audit.record("mfa.disable", actor=current_user, request=request, db=db)
    return _user_response(current_user)
