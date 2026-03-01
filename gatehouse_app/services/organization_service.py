"""Organization service."""
import logging
from datetime import datetime, timezone
from flask import current_app
from gatehouse_app.extensions import db
from gatehouse_app.models.organization.organization import Organization
from gatehouse_app.models.organization.organization_member import OrganizationMember
from gatehouse_app.exceptions.validation_exceptions import OrganizationNotFoundError, ConflictError
from gatehouse_app.utils.constants import OrganizationRole, AuditAction
from gatehouse_app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class OrganizationService:
    """Service for organization operations."""

    @staticmethod
    def create_organization(name, slug, owner_user_id, description=None, logo_url=None):
        """
        Create a new organization.

        Args:
            name: Organization name
            slug: Unique organization slug
            owner_user_id: ID of the user who will be the owner
            description: Optional description
            logo_url: Optional logo URL

        Returns:
            Organization instance

        Raises:
            ConflictError: If slug already exists
        """
        # Check if slug already exists
        existing = Organization.query.filter_by(slug=slug, deleted_at=None).first()
        if existing:
            raise ConflictError("Organization slug already exists")

        # Create organization
        org = Organization(
            name=name,
            slug=slug,
            description=description,
            logo_url=logo_url,
            is_active=True,
        )
        org.save()

        # Add owner as member
        member = OrganizationMember(
            user_id=owner_user_id,
            organization_id=org.id,
            role=OrganizationRole.OWNER,
            joined_at=datetime.now(timezone.utc),
        )
        member.save()

        # Log organization creation
        AuditService.log_action(
            action=AuditAction.ORG_CREATE,
            user_id=owner_user_id,
            organization_id=org.id,
            resource_type="organization",
            resource_id=org.id,
            description=f"Organization created: {name}",
        )

        return org

    @staticmethod
    def get_organization_by_id(org_id):
        """
        Get organization by ID.

        Args:
            org_id: Organization ID

        Returns:
            Organization instance

        Raises:
            OrganizationNotFoundError: If organization not found
        """
        org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
        
        # Development-only debug logging for organization validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Org] Get organization by ID: org_id={org_id}, exists={org is not None}")
        
        if not org:
            raise OrganizationNotFoundError()
        return org

    @staticmethod
    def get_organization_by_slug(slug):
        """
        Get organization by slug.

        Args:
            slug: Organization slug

        Returns:
            Organization instance or None
        """
        org = Organization.query.filter_by(slug=slug, deleted_at=None).first()
        
        # Development-only debug logging for organization validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Org] Get organization by slug: slug={slug}, exists={org is not None}")
        
        return org

    @staticmethod
    def update_organization(org, user_id, **kwargs):
        """
        Update organization.

        Args:
            org: Organization instance
            user_id: ID of user performing the update
            **kwargs: Fields to update

        Returns:
            Updated Organization instance
        """
        allowed_fields = ["name", "description", "logo_url"]
        update_data = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if update_data:
            org.update(**update_data)

            # Log organization update
            AuditService.log_action(
                action=AuditAction.ORG_UPDATE,
                user_id=user_id,
                organization_id=org.id,
                resource_type="organization",
                resource_id=org.id,
                metadata=update_data,
                description="Organization updated",
            )

        return org

    @staticmethod
    def delete_organization(org, user_id, soft=True):
        """
        Delete organization.

        Args:
            org: Organization instance
            user_id: ID of user performing the delete
            soft: If True, performs soft delete

        Returns:
            Deleted Organization instance
        """
        org.delete(soft=soft)

        # Log organization deletion
        AuditService.log_action(
            action=AuditAction.ORG_DELETE,
            user_id=user_id,
            organization_id=org.id,
            resource_type="organization",
            resource_id=org.id,
            description=f"Organization {'soft' if soft else 'hard'} deleted",
        )

        return org

    @staticmethod
    def add_member(org, user_id, role, inviter_id):
        """
        Add a member to the organization.

        Args:
            org: Organization instance
            user_id: ID of user to add
            role: OrganizationRole
            inviter_id: ID of user performing the invitation

        Returns:
            OrganizationMember instance

        Raises:
            ConflictError: If user is already a member
        """
        # Check if already a member
        existing = OrganizationMember.query.filter_by(
            user_id=user_id,
            organization_id=org.id,
            deleted_at=None,
        ).first()

        # Development-only debug logging for membership validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Org] Member check: org_id={org.id}, user_id={user_id}, already_member={existing is not None}")

        if existing:
            raise ConflictError("User is already a member of this organization")

        # Create membership
        member = OrganizationMember(
            user_id=user_id,
            organization_id=org.id,
            role=role,
            invited_by_id=inviter_id,
            invited_at=datetime.now(timezone.utc),
            joined_at=datetime.now(timezone.utc),
        )
        member.save()

        # Log member addition
        AuditService.log_action(
            action=AuditAction.ORG_MEMBER_ADD,
            user_id=inviter_id,
            organization_id=org.id,
            resource_type="organization_member",
            resource_id=member.id,
            metadata={"added_user_id": user_id, "role": role.value},
            description=f"Member added to organization with role: {role.value}",
        )

        return member

    @staticmethod
    def remove_member(org, user_id, remover_id):
        """
        Remove a member from the organization.

        Args:
            org: Organization instance
            user_id: ID of user to remove
            remover_id: ID of user performing the removal
        """
        member = OrganizationMember.query.filter_by(
            user_id=user_id,
            organization_id=org.id,
            deleted_at=None,
        ).first()

        # Development-only debug logging for membership removal validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Org] Member removal: org_id={org.id}, user_id={user_id}, found={member is not None}")

        if member:
            member.delete(soft=True)

            # Log member removal
            AuditService.log_action(
                action=AuditAction.ORG_MEMBER_REMOVE,
                user_id=remover_id,
                organization_id=org.id,
                resource_type="organization_member",
                resource_id=member.id,
                metadata={"removed_user_id": user_id},
                description="Member removed from organization",
            )

    @staticmethod
    def update_member_role(org, user_id, new_role, updater_id):
        """
        Update a member's role in the organization.

        Args:
            org: Organization instance
            user_id: ID of user whose role to update
            new_role: New OrganizationRole
            updater_id: ID of user performing the update

        Returns:
            Updated OrganizationMember instance
        """
        member = OrganizationMember.query.filter_by(
            user_id=user_id,
            organization_id=org.id,
            deleted_at=None,
        ).first()

        if member:
            old_role = member.role
            member.role = new_role
            db.session.commit()

            # Log role change
            AuditService.log_action(
                action=AuditAction.ORG_MEMBER_ROLE_CHANGE,
                user_id=updater_id,
                organization_id=org.id,
                resource_type="organization_member",
                resource_id=member.id,
                metadata={
                    "target_user_id": user_id,
                    "old_role": old_role.value,
                    "new_role": new_role.value,
                },
                description=f"Member role changed from {old_role.value} to {new_role.value}",
            )

        return member
