import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class IdTime:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, nullable=False)


class User(IdTime, Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Organization(IdTime, Base):
    __tablename__ = "organizations"
    name: Mapped[str] = mapped_column(String(128))
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)


class OrganizationMember(IdTime, Base):
    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False)


class Project(IdTime, Base):
    __tablename__ = "projects"
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))


class Environment(IdTime, Base):
    __tablename__ = "environments"
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    inherits_from_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("environments.id"), nullable=True)


class SecretKey(IdTime, Base):
    __tablename__ = "secret_keys"
    __table_args__ = (UniqueConstraint("environment_id", "key_name"),)
    environment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"), index=True)
    key_name: Mapped[str] = mapped_column(String(255))
    active_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")


class SecretVersion(IdTime, Base):
    __tablename__ = "secret_versions"
    __table_args__ = (UniqueConstraint("secret_key_id", "version"),)
    secret_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("secret_keys.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    ciphertext: Mapped[str] = mapped_column(Text)  # never plaintext
    nonce: Mapped[str] = mapped_column(String(64))
    wrapped_dek: Mapped[str] = mapped_column(Text)
    wrapped_dek_nonce: Mapped[str] = mapped_column(String(64))
    encryption_version: Mapped[int] = mapped_column(Integer)
    metadata_json: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    created_by_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


class ServiceToken(IdTime, Base):
    __tablename__ = "service_tokens"
    prefix: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    environment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"), nullable=True)
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ApiKey(IdTime, Base):
    __tablename__ = "api_keys"
    prefix: Mapped[str] = mapped_column(String(32), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AccessPolicy(IdTime, Base):
    __tablename__ = "access_policies"
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    member_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organization_members.id", ondelete="CASCADE"))
    resource_type: Mapped[str] = mapped_column(String(32))
    resource_id: Mapped[uuid.UUID] = mapped_column()
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)


class AuditLog(IdTime, Base):
    __tablename__ = "audit_logs"
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    event: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(64))
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)  # no values/diffs

