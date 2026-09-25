import hmac
import secrets
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from .authorization import require_permission
from .config import settings
from .crypto import EncryptedSecret, decrypt_value, encrypt_value
from .db import database
from .models import AuditLog, Environment, Organization, OrganizationMember, Project, Role, SecretKey, SecretVersion, ServiceToken, User, now
from .security import hash_password, new_token, token_digest, verify_password

cfg = settings()
app = FastAPI(title="KeyNest API", version="1.0.0", docs_url=None if cfg.production else "/docs")
app.add_middleware(CORSMiddleware, allow_origins=[cfg.public_origin], allow_credentials=True, allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"])

# Memory-only defensive limiter. Production deployments should also rate-limit at the proxy.
attempts: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(request: Request, bucket: str, count: int = 10, seconds: int = 60) -> None:
    key = f"{bucket}:{request.client.host if request.client else 'unknown'}"
    now_ts = time.monotonic()
    values = attempts[key]
    while values and values[0] <= now_ts - seconds:
        values.popleft()
    if len(values) >= count:
        raise HTTPException(429, "too many requests")
    values.append(now_ts)


def audit(db: Session, organization_id: uuid.UUID, actor_id: uuid.UUID | None, event: str, target_type: str, target_id: str) -> None:
    # Values, key diffs, IP addresses and headers intentionally never enter audit metadata.
    db.add(AuditLog(organization_id=organization_id, actor_id=actor_id, event=event, target_type=target_type, target_id=target_id, metadata_json={}))


def issue_session(user: User) -> str:
    return jwt.encode({"sub": str(user.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=15), "typ": "user"}, cfg.session_secret, algorithm="HS256")


def current_user(request: Request, db: Session = Depends(database)) -> User:
    token = request.cookies.get("keynest_session")
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        token = header.removeprefix("Bearer ")
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    # Cookie-authenticated writes require a double-submit CSRF token. Bearer clients are
    # not ambient credentials and are protected by CORS/TLS instead.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not header.startswith("Bearer "):
        csrf_cookie = request.cookies.get("keynest_csrf", "")
        csrf_header = request.headers.get("X-CSRF-Token", "")
        if not csrf_cookie or not hmac.compare_digest(csrf_cookie, csrf_header):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")
    try:
        claims = jwt.decode(token, cfg.session_secret, algorithms=["HS256"])
        user_id = uuid.UUID(claims["sub"])
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session") from exc
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session")
    return user


def project_org(db: Session, project_id: uuid.UUID) -> tuple[Project, uuid.UUID]:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "resource not found")
    return project, project.organization_id


def environment_org(db: Session, environment_id: uuid.UUID) -> tuple[Environment, uuid.UUID]:
    environment = db.get(Environment, environment_id)
    if environment is None:
        raise HTTPException(404, "resource not found")
    _, organization_id = project_org(db, environment.project_id)
    return environment, organization_id


class Register(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=1024)


class Login(Register):
    pass


class OrganizationIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    slug: str = Field(pattern=r"^[a-z0-9-]{2,80}$")


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class EnvironmentIn(ProjectIn):
    inherits_from_id: uuid.UUID | None = None


class SecretIn(BaseModel):
    key_name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=255)
    value: str = Field(max_length=262144)


class TokenIn(BaseModel):
    project_id: uuid.UUID
    environment_id: uuid.UUID | None = None
    permissions: list[str] = Field(min_length=1, max_length=20)
    expires_at: datetime


def current_service_token(request: Request, db: Session = Depends(database)) -> ServiceToken:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer knst_"):
        raise HTTPException(401, "service authentication required")
    token = header.removeprefix("Bearer ")
    service_token = db.query(ServiceToken).filter_by(token_hash=token_digest(token)).one_or_none()
    if not service_token or service_token.revoked_at or service_token.expires_at <= now():
        raise HTTPException(401, "invalid or expired service token")
    return service_token


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
    })
    return response


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/auth/register", status_code=201)
def register(body: Register, request: Request, db: Session = Depends(database)) -> dict[str, str]:
    rate_limit(request, "register", 5, 3600)
    if db.query(User).filter_by(email=body.email.lower()).first():
        raise HTTPException(409, "account already exists")
    user = User(email=body.email.lower(), password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": str(user.id)}


@app.post("/api/v1/auth/login")
def login(body: Login, request: Request, response: Response, db: Session = Depends(database)) -> dict[str, str]:
    rate_limit(request, "login")
    user = db.query(User).filter_by(email=body.email.lower()).one_or_none()
    if not user or not verify_password(user.password_hash, body.password):
        raise HTTPException(401, "invalid credentials")
    token = issue_session(user)
    response.set_cookie("keynest_session", token, httponly=True, secure=cfg.production, samesite="strict", max_age=900)
    response.set_cookie("keynest_csrf", secrets.token_urlsafe(24), httponly=False, secure=cfg.production, samesite="strict", max_age=900)
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/v1/organizations", status_code=201)
def create_organization(body: OrganizationIn, user: User = Depends(current_user), db: Session = Depends(database)) -> dict[str, str]:
    organization = Organization(name=body.name, slug=body.slug)
    db.add(organization)
    db.flush()
    db.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role=Role.OWNER))
    audit(db, organization.id, user.id, "organization.created", "organization", str(organization.id))
    db.commit()
    return {"id": str(organization.id), "slug": organization.slug}


@app.post("/api/v1/organizations/{organization_id}/projects", status_code=201)
def create_project(organization_id: uuid.UUID, body: ProjectIn, user: User = Depends(current_user), db: Session = Depends(database)) -> dict[str, str]:
    require_permission(db, user.id, organization_id, "secret:create")
    project = Project(organization_id=organization_id, name=body.name)
    db.add(project)
    db.commit()
    return {"id": str(project.id)}


@app.post("/api/v1/projects/{project_id}/environments", status_code=201)
def create_environment(project_id: uuid.UUID, body: EnvironmentIn, user: User = Depends(current_user), db: Session = Depends(database)) -> dict[str, str]:
    _, organization_id = project_org(db, project_id)
    require_permission(db, user.id, organization_id, "secret:create")
    if body.inherits_from_id:
        parent, _ = environment_org(db, body.inherits_from_id)
        if parent.project_id != project_id:
            raise HTTPException(400, "inheritance must remain within project")
    environment = Environment(project_id=project_id, name=body.name, inherits_from_id=body.inherits_from_id)
    db.add(environment)
    db.commit()
    return {"id": str(environment.id)}


@app.get("/api/v1/environments/{environment_id}/secrets")
def list_secrets(environment_id: uuid.UUID, user: User = Depends(current_user), db: Session = Depends(database)) -> list[dict[str, object]]:
    _, organization_id = environment_org(db, environment_id)
    require_permission(db, user.id, organization_id, "secret:list_names")
    rows = db.query(SecretKey).filter_by(environment_id=environment_id).all()
    return [{"id": str(row.id), "key_name": row.key_name, "active_version": row.active_version, "status": row.status, "expires_at": row.expires_at, "updated_at": row.created_at} for row in rows]


@app.post("/api/v1/environments/{environment_id}/secrets", status_code=201)
def set_secret(environment_id: uuid.UUID, body: SecretIn, user: User = Depends(current_user), db: Session = Depends(database)) -> dict[str, object]:
    _, organization_id = environment_org(db, environment_id)
    require_permission(db, user.id, organization_id, "secret:update")
    key = db.query(SecretKey).filter_by(environment_id=environment_id, key_name=body.key_name).one_or_none()
    if key is None:
        key = SecretKey(environment_id=environment_id, key_name=body.key_name)
        db.add(key)
        db.flush()
        version = 1
        event = "secret.created"
    else:
        version = (key.active_version or 0) + 1
        event = "secret.changed"
    aad = f"keynest:v1:{organization_id}:{key.id}:{version}".encode()
    encrypted = encrypt_value(body.value, cfg.master_key_bytes(), aad)
    db.add(SecretVersion(secret_key_id=key.id, version=version, ciphertext=encrypted.ciphertext, nonce=encrypted.nonce, wrapped_dek=encrypted.wrapped_dek, wrapped_dek_nonce=encrypted.wrapped_dek_nonce, encryption_version=encrypted.encryption_version, metadata_json={}, created_by_id=user.id))
    key.active_version = version
    audit(db, organization_id, user.id, event, "secret", str(key.id))
    db.commit()
    return {"id": str(key.id), "key_name": key.key_name, "active_version": version}


@app.post("/api/v1/secrets/{secret_id}/reveal")
def reveal_secret(secret_id: uuid.UUID, user: User = Depends(current_user), db: Session = Depends(database)) -> dict[str, str]:
    key = db.get(SecretKey, secret_id)
    if not key or key.active_version is None:
        raise HTTPException(404, "resource not found")
    _, organization_id = environment_org(db, key.environment_id)
    require_permission(db, user.id, organization_id, "secret:read_values")
    version = db.query(SecretVersion).filter_by(secret_key_id=key.id, version=key.active_version).one()
    aad = f"keynest:v1:{organization_id}:{key.id}:{version.version}".encode()
    value = decrypt_value(EncryptedSecret(version.ciphertext, version.nonce, version.wrapped_dek, version.wrapped_dek_nonce, version.encryption_version), cfg.master_key_bytes(), aad)
    audit(db, organization_id, user.id, "secret.revealed", "secret", str(key.id))
    db.commit()
    return {"key_name": key.key_name, "value": value}


@app.post("/api/v1/service-tokens", status_code=201)
def create_token(body: TokenIn, user: User = Depends(current_user), db: Session = Depends(database)) -> dict[str, object]:
    _, organization_id = project_org(db, body.project_id)
    require_permission(db, user.id, organization_id, "token:create")
    if body.expires_at <= now():
        raise HTTPException(400, "token expiry must be in the future")
    if body.environment_id:
        env, _ = environment_org(db, body.environment_id)
        if env.project_id != body.project_id:
            raise HTTPException(400, "environment not in project")
    plaintext, prefix, digest = new_token()
    service_token = ServiceToken(prefix=prefix, token_hash=digest, project_id=body.project_id, environment_id=body.environment_id, permissions=body.permissions, expires_at=body.expires_at)
    db.add(service_token)
    audit(db, organization_id, user.id, "service_token.created", "service_token", str(service_token.id))
    db.commit()
    return {"id": str(service_token.id), "token": plaintext, "warning": "Copy this token now. It will not be shown again."}


@app.post("/api/v1/service-tokens/{token_id}/revoke", status_code=204)
def revoke_token(token_id: uuid.UUID, user: User = Depends(current_user), db: Session = Depends(database)) -> Response:
    service_token = db.get(ServiceToken, token_id)
    if service_token is None:
        raise HTTPException(404, "resource not found")
    _, organization_id = project_org(db, service_token.project_id)
    require_permission(db, user.id, organization_id, "token:revoke")
    service_token.revoked_at = now()
    audit(db, organization_id, user.id, "service_token.revoked", "service_token", str(token_id))
    db.commit()
    return Response(status_code=204)


@app.get("/api/v1/cli/environments/{environment_id}/values")
def cli_values(environment_id: uuid.UUID, request: Request, service_token: ServiceToken = Depends(current_service_token), db: Session = Depends(database)) -> JSONResponse:
    """Dedicated CLI-only value endpoint. List APIs never contain ciphertext or plaintext."""
    rate_limit(request, "cli-values", 60, 60)
    environment, organization_id = environment_org(db, environment_id)
    if environment.project_id != service_token.project_id or (service_token.environment_id and service_token.environment_id != environment_id):
        raise HTTPException(404, "resource not found")
    if "secret:read_values" not in service_token.permissions:
        raise HTTPException(403, "permission denied")
    result: dict[str, str] = {}
    for key in db.query(SecretKey).filter_by(environment_id=environment_id).all():
        if key.active_version is None:
            continue
        version = db.query(SecretVersion).filter_by(secret_key_id=key.id, version=key.active_version).one()
        aad = f"keynest:v1:{organization_id}:{key.id}:{version.version}".encode()
        result[key.key_name] = decrypt_value(EncryptedSecret(version.ciphertext, version.nonce, version.wrapped_dek, version.wrapped_dek_nonce, version.encryption_version), cfg.master_key_bytes(), aad)
    # Do not audit values. Audit the access event only.
    audit(db, organization_id, None, "secret.injected", "environment", str(environment_id))
    db.commit()
    return JSONResponse(content={"values": result}, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
