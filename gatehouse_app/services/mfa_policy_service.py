"""MFA Policy Service."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from gatehouse_app.extensions import db
from gatehouse_app.models.security.organization_security_policy import OrganizationSecurityPolicy
from gatehouse_app.models.security.user_security_policy import UserSecurityPolicy
from gatehouse_app.models.security.mfa_policy_compliance import MfaPolicyCompliance
from gatehouse_app.models.user.user import User
from gatehouse_app.models.organization.organization import Organization
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.utils.constants import (
    MfaPolicyMode,
    MfaComplianceStatus,
    MfaRequirementOverride,
    AuditAction,
    UserStatus,
)


@dataclass
class OrgPolicyDto:
    """DTO for organization policy."""
    organization_id: str
    mfa_policy_mode: str
    mfa_grace_period_days: int
    notify_days_before: int
    policy_version: int
    updated_by_user_id: Optional[str] = None


@dataclass
class EffectiveUserPolicyDto:
    """DTO for effective user policy combining org and user overrides."""
    organization_id: str
    effective_mode: str
    requires_totp: bool
    requires_webauthn: bool
    grace_period_days: int
    is_exempt: bool = False


@dataclass
class UserMfaStateDto:
    """DTO for per-organization MFA state."""
    organization_id: str
    organization_name: str
    status: str
    effective_mode: str
    deadline_at: Optional[str] = None
    applied_at: Optional[str] = None


@dataclass
class AggregateMfaStateDto:
    """DTO for aggregate MFA state across all organizations."""
    overall_status: str
    missing_methods: List[str] = field(default_factory=list)
    deadline_at: Optional[str] = None
    orgs: List[UserMfaStateDto] = field(default_factory=list)


@dataclass
class LoginPolicyResult:
    """Result of policy evaluation after primary auth success."""
    can_create_full_session: bool
    create_compliance_only_session: bool
    compliance_summary: AggregateMfaStateDto


class MfaPolicyService:
    """Service for MFA policy evaluation and compliance tracking."""

    @staticmethod
    def get_org_policy(org_id: str) -> Optional[OrgPolicyDto]:
        """Get organization security policy.

        Args:
            org_id: Organization ID

        Returns:
            OrgPolicyDto or None if not found
        """
        policy = OrganizationSecurityPolicy.query.filter_by(
            organization_id=org_id, deleted_at=None
        ).first()

        if not policy:
            return None

        return OrgPolicyDto(
            organization_id=policy.organization_id,
            mfa_policy_mode=policy.mfa_policy_mode.value,
            mfa_grace_period_days=policy.mfa_grace_period_days,
            notify_days_before=policy.notify_days_before,
            policy_version=policy.policy_version,
            updated_by_user_id=policy.updated_by_user_id,
        )

    @staticmethod
    def get_effective_user_policy(
        user_id: str, org_id: str
    ) -> EffectiveUserPolicyDto:
        """Get effective user policy combining org policy with user overrides.

        Args:
            user_id: User ID
            org_id: Organization ID

        Returns:
            EffectiveUserPolicyDto
        """
        # Get org policy
        org_policy = OrganizationSecurityPolicy.query.filter_by(
            organization_id=org_id, deleted_at=None
        ).first()

        if not org_policy:
            # No org policy means no requirements
            return EffectiveUserPolicyDto(
                organization_id=org_id,
                effective_mode=MfaPolicyMode.DISABLED.value,
                requires_totp=False,
                requires_webauthn=False,
                grace_period_days=0,
                is_exempt=True,
            )

        # Get user override
        user_override = UserSecurityPolicy.query.filter_by(
            user_id=user_id, organization_id=org_id, deleted_at=None
        ).first()

        # Determine effective mode
        if user_override:
            override_mode = user_override.mfa_override_mode
            if override_mode == MfaRequirementOverride.EXEMPT:
                return EffectiveUserPolicyDto(
                    organization_id=org_id,
                    effective_mode=MfaPolicyMode.DISABLED.value,
                    requires_totp=False,
                    requires_webauthn=False,
                    grace_period_days=org_policy.mfa_grace_period_days,
                    is_exempt=True,
                )
            elif override_mode == MfaRequirementOverride.REQUIRED:
                # User is required to have MFA even if org is optional
                effective_mode = MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN
            else:
                effective_mode = org_policy.mfa_policy_mode
        else:
            effective_mode = org_policy.mfa_policy_mode

        # Determine required methods based on mode
        requires_totp = effective_mode in (
            MfaPolicyMode.REQUIRE_TOTP,
            MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
        )
        requires_webauthn = effective_mode in (
            MfaPolicyMode.REQUIRE_WEBAUTHN,
            MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN,
        )

        return EffectiveUserPolicyDto(
            organization_id=org_id,
            effective_mode=effective_mode.value,
            requires_totp=requires_totp,
            requires_webauthn=requires_webauthn,
            grace_period_days=org_policy.mfa_grace_period_days,
            is_exempt=False,
        )

    @staticmethod
    def evaluate_user_mfa_state(user: User) -> AggregateMfaStateDto:
        """Evaluate user's MFA state across all organizations.

        Args:
            user: User instance

        Returns:
            AggregateMfaStateDto with overall status and per-org breakdown
        """
        org_states: List[UserMfaStateDto] = []
        overall_status = MfaComplianceStatus.COMPLIANT.value
        earliest_deadline: Optional[datetime] = None
        missing_methods: set = set()

        for membership in user.organization_memberships:
            if membership.deleted_at is not None:
                continue

            org = membership.organization
            if org.deleted_at is not None:
                continue

            effective_policy = MfaPolicyService.get_effective_user_policy(
                user.id, org.id
            )

            # Get or create compliance record
            compliance = MfaPolicyCompliance.query.filter_by(
                user_id=user.id, organization_id=org.id, deleted_at=None
            ).first()

            if not compliance:
                # Create initial compliance record
                compliance = MfaPolicyCompliance(
                    user_id=user.id,
                    organization_id=org.id,
                    status=MfaComplianceStatus.NOT_APPLICABLE,
                    policy_version=0,
                )
                compliance.save()

            # Determine status based on policy and user MFA state
            status = MfaPolicyService._evaluate_compliance_status(
                user, effective_policy, compliance
            )

            # Update compliance record if needed
            if compliance.status != status:
                compliance.status = status
                db.session.commit()

            # Track missing methods
            if status not in (
                MfaComplianceStatus.COMPLIANT.value,
                MfaComplianceStatus.NOT_APPLICABLE.value,
            ):
                if effective_policy.requires_totp and not user.has_totp_enabled():
                    missing_methods.add("totp")
                if effective_policy.requires_webauthn and not user.has_webauthn_enabled():
                    missing_methods.add("webauthn")

            # Track earliest deadline
            if compliance.deadline_at:
                if earliest_deadline is None or compliance.deadline_at < earliest_deadline:
                    earliest_deadline = compliance.deadline_at

            # Determine overall status (most restrictive)
            if status == MfaComplianceStatus.SUSPENDED.value:
                overall_status = MfaComplianceStatus.SUSPENDED.value
            elif (
                status == MfaComplianceStatus.PAST_DUE.value
                and overall_status != MfaComplianceStatus.SUSPENDED.value
            ):
                overall_status = MfaComplianceStatus.PAST_DUE.value
            elif (
                status == MfaComplianceStatus.IN_GRACE.value
                and overall_status
                not in (
                    MfaComplianceStatus.SUSPENDED.value,
                    MfaComplianceStatus.PAST_DUE.value,
                )
            ):
                overall_status = MfaComplianceStatus.IN_GRACE.value
            elif (
                status == MfaComplianceStatus.PENDING.value
                and overall_status == MfaComplianceStatus.COMPLIANT.value
            ):
                overall_status = MfaComplianceStatus.PENDING.value

            org_states.append(
                UserMfaStateDto(
                    organization_id=org.id,
                    organization_name=org.name,
                    status=status,
                    effective_mode=effective_policy.effective_mode,
                    deadline_at=compliance.deadline_at.isoformat() if compliance.deadline_at else None,
                    applied_at=compliance.applied_at.isoformat() if compliance.applied_at else None,
                )
            )

        return AggregateMfaStateDto(
            overall_status=overall_status,
            missing_methods=list(missing_methods),
            deadline_at=earliest_deadline.isoformat() if earliest_deadline else None,
            orgs=org_states,
        )

    @staticmethod
    def _evaluate_compliance_status(
        user: User,
        effective_policy: EffectiveUserPolicyDto,
        compliance: MfaPolicyCompliance,
    ) -> str:
        """Evaluate compliance status for a user in an organization.

        Args:
            user: User instance
            effective_policy: EffectiveUserPolicyDto
            compliance: MfaPolicyCompliance instance

        Returns:
            Status string
        """
        now = datetime.now(timezone.utc)

        # If exempt or disabled, mark as not applicable
        if effective_policy.is_exempt:
            return MfaComplianceStatus.NOT_APPLICABLE.value

        if effective_policy.effective_mode == MfaPolicyMode.DISABLED.value:
            return MfaComplianceStatus.NOT_APPLICABLE.value

        # Check if user has required MFA methods
        has_totp = user.has_totp_enabled()
        has_webauthn = user.has_webauthn_enabled()

        has_required = (
            (not effective_policy.requires_totp or has_totp)
            and (not effective_policy.requires_webauthn or has_webauthn)
        )

        if has_required:
            return MfaComplianceStatus.COMPLIANT.value

        # User is missing required MFA
        # If no deadline set, set it now
        if not compliance.deadline_at and effective_policy.grace_period_days > 0:
            compliance.applied_at = now
            compliance.deadline_at = now.replace(
                tzinfo=None
            ) + __import__("datetime").timedelta(
                days=effective_policy.grace_period_days
            )
            db.session.commit()
            return MfaComplianceStatus.IN_GRACE.value

        # Check deadline
        if compliance.deadline_at:
            deadline = compliance.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)

            if now < deadline:
                return MfaComplianceStatus.IN_GRACE.value
            else:
                return MfaComplianceStatus.PAST_DUE.value

        return MfaComplianceStatus.PENDING.value

    @staticmethod
    def after_primary_auth_success(
        user: User, remember_me: bool = False
    ) -> LoginPolicyResult:
        """Determine session type based on compliance after primary auth success.

        Args:
            user: User instance
            remember_me: Whether this is a remember-me session

        Returns:
            LoginPolicyResult with session type and compliance summary
        """
        compliance_summary = MfaPolicyService.evaluate_user_mfa_state(user)

        # Check if there are any REQUIRED policies affecting this user
        has_required_policy = False
        for org_state in compliance_summary.orgs:
            if org_state.effective_mode in (
                MfaPolicyMode.REQUIRE_TOTP.value,
                MfaPolicyMode.REQUIRE_WEBAUTHN.value,
                MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value,
            ):
                has_required_policy = True
                break

        if not has_required_policy:
            # No required policies, full session allowed
            return LoginPolicyResult(
                can_create_full_session=True,
                create_compliance_only_session=False,
                compliance_summary=compliance_summary,
            )

        # Check if user is compliant
        if compliance_summary.overall_status == MfaComplianceStatus.COMPLIANT.value:
            return LoginPolicyResult(
                can_create_full_session=True,
                create_compliance_only_session=False,
                compliance_summary=compliance_summary,
            )

        # User is not compliant
        if compliance_summary.overall_status in (
            MfaComplianceStatus.IN_GRACE.value,
            MfaComplianceStatus.PENDING.value,
        ):
            # Can proceed with full session but warnings
            return LoginPolicyResult(
                can_create_full_session=True,
                create_compliance_only_session=False,
                compliance_summary=compliance_summary,
            )

        # Past due or suspended - compliance only session
        return LoginPolicyResult(
            can_create_full_session=False,
            create_compliance_only_session=True,
            compliance_summary=compliance_summary,
        )

    @staticmethod
    def transition_to_suspended_if_past_due(now: Optional[datetime] = None) -> int:
        """Scheduled job to transition past-due users to suspended status.

        Args:
            now: Current time, defaults to now

        Returns:
            Number of users transitioned to suspended
        """
        if now is None:
            now = datetime.now(timezone.utc)

        suspended_count = 0

        # Find all compliance records that are past due
        past_due_records = MfaPolicyCompliance.query.filter(
            MfaPolicyCompliance.status == MfaComplianceStatus.PAST_DUE,
            MfaPolicyCompliance.deadline_at != None,
            MfaPolicyCompliance.deleted_at == None,
        ).all()

        for record in past_due_records:
            deadline = record.deadline_at
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)

            if now >= deadline:
                # Transition to suspended
                record.status = MfaComplianceStatus.SUSPENDED
                record.suspended_at = now
                db.session.commit()

                # Update user status
                user = User.query.get(record.user_id)
                if user and user.status != UserStatus.COMPLIANCE_SUSPENDED:
                    user.status = UserStatus.COMPLIANCE_SUSPENDED
                    db.session.commit()

                    # Audit log
                    AuditService.log_action(
                        action=AuditAction.MFA_POLICY_USER_SUSPENDED,
                        user_id=record.user_id,
                        organization_id=record.organization_id,
                        description=f"User suspended due to MFA compliance deadline passed",
                    )

                suspended_count += 1

        return suspended_count

    @staticmethod
    def create_org_policy(
        organization_id: str,
        mfa_policy_mode: MfaPolicyMode,
        mfa_grace_period_days: int = 14,
        notify_days_before: int = 7,
        updated_by_user_id: Optional[str] = None,
    ) -> OrganizationSecurityPolicy:
        """Create or update organization security policy.

        Args:
            organization_id: Organization ID
            mfa_policy_mode: MFA policy mode
            mfa_grace_period_days: Grace period in days
            notify_days_before: Days before deadline to notify
            updated_by_user_id: User making the change

        Returns:
            OrganizationSecurityPolicy instance
        """
        policy = OrganizationSecurityPolicy.query.filter_by(
            organization_id=organization_id, deleted_at=None
        ).first()

        if policy:
            # Update existing
            old_mode = policy.mfa_policy_mode
            policy.mfa_policy_mode = mfa_policy_mode
            policy.mfa_grace_period_days = mfa_grace_period_days
            policy.notify_days_before = notify_days_before
            policy.policy_version += 1
            policy.updated_by_user_id = updated_by_user_id
            policy.save()

            # Audit log
            AuditService.log_action(
                action=AuditAction.ORG_SECURITY_POLICY_UPDATE,
                user_id=updated_by_user_id,
                organization_id=organization_id,
                description=f"Security policy updated from {old_mode.value} to {mfa_policy_mode.value}",
            )
        else:
            # Create new
            policy = OrganizationSecurityPolicy(
                organization_id=organization_id,
                mfa_policy_mode=mfa_policy_mode,
                mfa_grace_period_days=mfa_grace_period_days,
                notify_days_before=notify_days_before,
                policy_version=1,
                updated_by_user_id=updated_by_user_id,
            )
            policy.save()

            # Audit log
            AuditService.log_action(
                action=AuditAction.ORG_SECURITY_POLICY_UPDATE,
                user_id=updated_by_user_id,
                organization_id=organization_id,
                description=f"Security policy created with mode {mfa_policy_mode.value}",
            )

        return policy

    @staticmethod
    def set_user_override(
        user_id: str,
        organization_id: str,
        mfa_override_mode: MfaRequirementOverride,
        force_totp: bool = False,
        force_webauthn: bool = False,
        updated_by_user_id: Optional[str] = None,
    ) -> UserSecurityPolicy:
        """Set user security policy override.

        Args:
            user_id: User ID
            organization_id: Organization ID
            mfa_override_mode: Override mode
            force_totp: Force TOTP requirement
            force_webauthn: Force WebAuthn requirement
            updated_by_user_id: User making the change

        Returns:
            UserSecurityPolicy instance
        """
        override = UserSecurityPolicy.query.filter_by(
            user_id=user_id, organization_id=organization_id, deleted_at=None
        ).first()

        if override:
            old_mode = override.mfa_override_mode
            override.mfa_override_mode = mfa_override_mode
            override.force_totp = force_totp
            override.force_webauthn = force_webauthn
            override.save()

            # Audit log
            AuditService.log_action(
                action=AuditAction.USER_SECURITY_POLICY_OVERRIDE_UPDATE,
                user_id=updated_by_user_id,
                organization_id=organization_id,
                resource_type="user",
                resource_id=user_id,
                description=f"User policy override updated from {old_mode.value} to {mfa_override_mode.value}",
            )
        else:
            override = UserSecurityPolicy(
                user_id=user_id,
                organization_id=organization_id,
                mfa_override_mode=mfa_override_mode,
                force_totp=force_totp,
                force_webauthn=force_webauthn,
            )
            override.save()

            # Audit log
            AuditService.log_action(
                action=AuditAction.USER_SECURITY_POLICY_OVERRIDE_UPDATE,
                user_id=updated_by_user_id,
                organization_id=organization_id,
                resource_type="user",
                resource_id=user_id,
                description=f"User policy override created with mode {mfa_override_mode.value}",
            )

        return override

    @staticmethod
    def get_user_compliance(user_id: str, organization_id: str) -> Optional[MfaPolicyCompliance]:
        """Get user compliance record for an organization.

        Args:
            user_id: User ID
            organization_id: Organization ID

        Returns:
            MfaPolicyCompliance or None
        """
        return MfaPolicyCompliance.query.filter_by(
            user_id=user_id, organization_id=organization_id, deleted_at=None
        ).first()

    @staticmethod
    def get_org_compliance_list(
        organization_id: str, status: Optional[MfaComplianceStatus] = None, limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get list of user compliance records for an organization.

        Args:
            organization_id: Organization ID
            status: Optional status filter
            limit: Maximum records to return
            offset: Offset for pagination

        Returns:
            List of compliance records with user info
        """
        query = db.session.query(
            MfaPolicyCompliance,
            User.email,
            User.full_name,
        ).join(
            User, User.id == MfaPolicyCompliance.user_id
        ).filter(
            MfaPolicyCompliance.organization_id == organization_id,
            MfaPolicyCompliance.deleted_at == None,
            User.deleted_at == None,
        )

        if status:
            query = query.filter(MfaPolicyCompliance.status == status)

        records = query.order_by(
            MfaPolicyCompliance.created_at.desc()
        ).limit(limit).offset(offset).all()

        result = []
        for compliance, email, full_name in records:
            result.append({
                "user_id": compliance.user_id,
                "email": email,
                "full_name": full_name,
                "status": compliance.status.value,
                "deadline_at": compliance.deadline_at.isoformat() if compliance.deadline_at else None,
                "applied_at": compliance.applied_at.isoformat() if compliance.applied_at else None,
                "compliant_at": compliance.compliant_at.isoformat() if compliance.compliant_at else None,
                "suspended_at": compliance.suspended_at.isoformat() if compliance.suspended_at else None,
                "notification_count": compliance.notification_count,
            })

        return result

    # =========================================================================
    # Multi-Organization Edge Case Handling
    # =========================================================================

    @staticmethod
    def get_strictest_mode(modes: List[str]) -> str:
        """Get the strictest MFA policy mode from a list.
        
        Used for multi-org scenarios where a user belongs to multiple organizations
        with different policies. "Most secure wins" logic determines the effective
        requirement.
        
        Args:
            modes: List of policy mode strings
            
        Returns:
            The strictest mode string
        """
        # Define strictness hierarchy (more strict = higher index)
        strictness_order = [
            MfaPolicyMode.DISABLED.value,
            MfaPolicyMode.OPTIONAL.value,
            MfaPolicyMode.REQUIRE_TOTP.value,
            MfaPolicyMode.REQUIRE_WEBAUTHN.value,
            MfaPolicyMode.REQUIRE_TOTP_OR_WEBAUTHN.value,
        ]
        
        max_strictness = -1
        result_mode = MfaPolicyMode.OPTIONAL.value
        
        for mode in modes:
            if mode in strictness_order:
                idx = strictness_order.index(mode)
                if idx > max_strictness:
                    max_strictness = idx
                    result_mode = mode
        
        return result_mode

    @staticmethod
    def reevaluate_all_org_compliance(organization_id: str, now: Optional[datetime] = None) -> int:
        """Reevaluate compliance for all users in an organization.
        
        Called when org policy changes to ensure all users are properly evaluated
        under the new policy. This handles the edge case where policy becomes
        more restrictive (e.g., OPTIONAL -> REQUIRE_TOTP).
        
        Args:
            organization_id: Organization ID
            now: Current time, defaults to now
            
        Returns:
            Number of compliance records updated
        """
        if now is None:
            now = datetime.now(timezone.utc)
        
        from gatehouse_app.models.organization.organization_member import OrganizationMember
        
        updated_count = 0
        
        # Get all active members of the organization
        memberships = OrganizationMember.query.filter_by(
            organization_id=organization_id, deleted_at=None
        ).all()
        
        for membership in memberships:
            user = membership.user
            if not user or user.deleted_at is not None:
                continue
            
            # Get or create compliance record
            compliance = MfaPolicyCompliance.query.filter_by(
                user_id=user.id, organization_id=organization_id, deleted_at=None
            ).first()
            
            if not compliance:
                compliance = MfaPolicyCompliance(
                    user_id=user.id,
                    organization_id=organization_id,
                    status=MfaComplianceStatus.NOT_APPLICABLE,
                    policy_version=0,
                )
                compliance.save()
            
            # Reevaluate under new policy
            effective_policy = MfaPolicyService.get_effective_user_policy(
                user.id, organization_id
            )
            
            old_status = compliance.status.value if hasattr(compliance.status, 'value') else str(compliance.status)
            new_status = MfaPolicyService._evaluate_compliance_status(
                user, effective_policy, compliance
            )
            
            if old_status != new_status:
                compliance.status = MfaComplianceStatus(new_status)
                # Reset deadline if transitioning to in_grace from a non-grace state
                if new_status == MfaComplianceStatus.IN_GRACE.value and not compliance.deadline_at:
                    compliance.applied_at = now
                    compliance.deadline_at = now.replace(tzinfo=None) + __import__("datetime").timedelta(
                        days=effective_policy.grace_period_days
                    )
                db.session.commit()
                updated_count += 1
                
                logger.info(
                    f"Reevaluated compliance for user {user.email} in org {organization_id}: "
                    f"{old_status} -> {new_status}"
                )
        
        return updated_count

    @staticmethod
    def check_and_restore_user_status(user_id: str) -> bool:
        """Check if user should be restored to ACTIVE status.
        
        Called after compliance changes to determine if a COMPLIANCE_SUSPENDED
        user should be restored to ACTIVE status. This happens when:
        - All org policies are now compliant
        - User overrides were changed to EXEMPT
        
        Args:
            user_id: User ID
            
        Returns:
            True if user status was restored, False otherwise
        """
        user = User.query.get(user_id)
        if not user:
            return False
        
        if user.status != UserStatus.COMPLIANCE_SUSPENDED:
            return False
        
        # Evaluate user's overall compliance state
        compliance_summary = MfaPolicyService.evaluate_user_mfa_state(user)
        
        # If now compliant across all orgs, restore status
        if compliance_summary.overall_status == MfaComplianceStatus.COMPLIANT.value:
            user.status = UserStatus.ACTIVE
            db.session.commit()
            
            # Audit log
            AuditService.log_action(
                action=AuditAction.MFA_POLICY_USER_COMPLIANT,
                user_id=user_id,
                description="User restored to ACTIVE status after becoming MFA compliant",
            )
            
            logger.info(f"User {user.email} restored to ACTIVE status")
            return True
        
        return False

    # =========================================================================
    # User Override Edge Case Handling
    # =========================================================================

    @staticmethod
    def get_override_summary(user_id: str, organization_id: str) -> Dict[str, Any]:
        """Get a summary of user override for an organization.
        
        Args:
            user_id: User ID
            organization_id: Organization ID
            
        Returns:
            Dictionary with override information
        """
        user_override = UserSecurityPolicy.query.filter_by(
            user_id=user_id, organization_id=organization_id, deleted_at=None
        ).first()
        
        org_policy = MfaPolicyService.get_org_policy(organization_id)
        
        if not user_override:
            return {
                "has_override": False,
                "mode": "inherit",
                "org_policy_mode": org_policy.mfa_policy_mode if org_policy else "none",
                "effective_mode": org_policy.mfa_policy_mode if org_policy else "disabled",
            }
        
        effective_policy = MfaPolicyService.get_effective_user_policy(
            user_id, organization_id
        )
        
        return {
            "has_override": True,
            "mode": user_override.mfa_override_mode.value,
            "force_totp": user_override.force_totp,
            "force_webauthn": user_override.force_webauthn,
            "org_policy_mode": org_policy.mfa_policy_mode if org_policy else "none",
            "effective_mode": effective_policy.effective_mode,
            "is_exempt": effective_policy.is_exempt,
        }

    # =========================================================================
    # Security Audit Logging
    # =========================================================================

    @staticmethod
    def log_suspended_login_attempt(user: User, ip_address: str = None, user_agent: str = None):
        """Log a login attempt by a compliance-suspended user.
        
        This provides audit trail for potential security incidents where
        suspended users attempt to access the system.
        
        Args:
            user: User instance
            ip_address: Client IP address
            user_agent: Client user agent
        """
        # Get current compliance summary
        compliance_summary = MfaPolicyService.evaluate_user_mfa_state(user)
        
        # Find which org(s) caused suspension
        suspended_orgs = [
            org for org in compliance_summary.orgs
            if org.status == MfaComplianceStatus.SUSPENDED.value
        ]
        
        org_ids = [org.organization_id for org in suspended_orgs]
        
        AuditService.log_action(
            action=AuditAction.USER_LOGIN,
            user_id=user.id,
            organization_id=org_ids[0] if org_ids else None,
            ip_address=ip_address,
            user_agent=user_agent,
            description=f"Login attempt while compliance suspended. Suspended orgs: {org_ids}",
            success=False,
            error_message="MFA compliance required",
        )

    @staticmethod
    def log_policy_bypass_attempt(
        user: User,
        endpoint: str,
        ip_address: str = None,
        user_agent: str = None,
    ):
        """Log a potential policy bypass attempt.
        
        Called when a compliance-only session attempts to access a
        full-access endpoint. This could indicate security issues.
        
        Args:
            user: User instance
            endpoint: Requested endpoint
            ip_address: Client IP address
            user_agent: Client user agent
        """
        AuditService.log_action(
            action=AuditAction.USER_LOGIN,  # Reusing USER_LOGIN for audit
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="endpoint",
            resource_id=endpoint,
            description=f"Policy bypass attempt - compliance-only session accessed {endpoint}",
            success=False,
            error_message="MFA compliance required",
        )

    @staticmethod
    def get_multi_org_aggregate_state(user: User) -> Dict[str, Any]:
        """Get aggregate MFA state for a user across all organizations.
        
        This provides detailed breakdown of how multi-org membership affects
        compliance status, useful for debugging and admin reporting.
        
        Args:
            user: User instance
            
        Returns:
            Dictionary with aggregate state details
        """
        compliance_summary = MfaPolicyService.evaluate_user_mfa_state(user)
        
        # Calculate strictest requirement
        modes = [org.effective_mode for org in compliance_summary.orgs]
        strictest_mode = MfaPolicyService.get_strictest_mode(modes)
        
        # Find organizations requiring MFA
        requiring_orgs = [
            {
                "organization_id": org.organization_id,
                "organization_name": org.organization_name,
                "mode": org.effective_mode,
                "status": org.status,
            }
            for org in compliance_summary.orgs
            if org.effective_mode not in (
                MfaPolicyMode.DISABLED.value,
                MfaPolicyMode.OPTIONAL.value,
            )
        ]
        
        # Find exempt organizations
        for org in compliance_summary.orgs:
            override_summary = MfaPolicyService.get_override_summary(
                user.id, org.organization_id
            )
            if override_summary.get("is_exempt"):
                requiring_orgs = [
                    o for o in requiring_orgs
                    if o["organization_id"] != org.organization_id
                ]
        
        return {
            "overall_status": compliance_summary.overall_status,
            "strictest_mode": strictest_mode,
            "missing_methods": compliance_summary.missing_methods,
            "deadline_at": compliance_summary.deadline_at,
            "requiring_org_count": len(requiring_orgs),
            "requiring_orgs": requiring_orgs,
            "total_org_count": len(compliance_summary.orgs),
            "per_org_details": [
                {
                    "organization_id": org.organization_id,
                    "organization_name": org.organization_name,
                    "effective_mode": org.effective_mode,
                    "status": org.status,
                    "deadline_at": org.deadline_at,
                    "applied_at": org.applied_at,
                }
                for org in compliance_summary.orgs
            ],
        }