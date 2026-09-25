import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from .models import AccessPolicy, OrganizationMember, Role

ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.OWNER: {"*"},
    Role.ADMIN: {"secret:list_names", "secret:read_values", "secret:create", "secret:update", "secret:delete", "secret:export", "token:create", "token:revoke", "audit:read", "member:manage"},
    Role.DEVELOPER: {"secret:list_names", "secret:read_values", "secret:create", "secret:update"},
    Role.VIEWER: {"secret:list_names"},
}


def require_permission(db: Session, user_id: uuid.UUID, organization_id: uuid.UUID, permission: str) -> OrganizationMember:
    member = db.query(OrganizationMember).filter_by(organization_id=organization_id, user_id=user_id).one_or_none()
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "resource not found")
    allowed = ROLE_PERMISSIONS[member.role]
    if "*" in allowed or permission in allowed:
        return member
    policies = db.query(AccessPolicy).filter_by(organization_id=organization_id, member_id=member.id).all()
    if any(permission in policy.permissions for policy in policies):
        return member
    raise HTTPException(status.HTTP_403_FORBIDDEN, "permission denied")

