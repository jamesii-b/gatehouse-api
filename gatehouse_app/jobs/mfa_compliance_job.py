"""MFA Compliance Scheduled Job.

This module implements the scheduled job for processing MFA compliance transitions,
sending notifications to users approaching deadlines, and handling edge cases.

The job is designed to be run periodically (e.g., via cron) to:
1. Transition users from PAST_DUE to SUSPENDED status
2. Send deadline reminder notifications to users in grace period
3. Update notification tracking metadata

Usage:
    python manage.py run_mfa_compliance_job

Or call directly:
    from gatehouse_app.jobs.mfa_compliance_job import process_mfa_compliance
    process_mfa_compliance()
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import logging

from gatehouse_app.extensions import db
from gatehouse_app.models.security.mfa_policy_compliance import MfaPolicyCompliance
from gatehouse_app.models.security.organization_security_policy import OrganizationSecurityPolicy
from gatehouse_app.models.user.user import User
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.services.notification_service import NotificationService
from gatehouse_app.utils.constants import MfaComplianceStatus

logger = logging.getLogger(__name__)


def process_mfa_compliance(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Process MFA compliance transitions and send notifications.

    This scheduled job performs the following operations:
    1. Transitions users from PAST_DUE to SUSPENDED status
    2. Identifies users approaching deadline (within notify_days_before)
    3. Sends deadline reminder notifications
    4. Updates notification tracking metadata

    Args:
        now: Current time, defaults to now (UTC)

    Returns:
        Dictionary with job execution statistics:
        - suspended_count: Number of users transitioned to suspended
        - notified_count: Number of notifications sent
        - processed_count: Total compliance records processed
    """
    if now is None:
        now = datetime.now(timezone.utc)

    logger.info(f"Starting MFA compliance job at {now.isoformat()}")

    stats = {
        "suspended_count": 0,
        "notified_count": 0,
        "processed_count": 0,
        "errors": [],
    }

    try:
        # Step 1: Transition past-due users to suspended
        suspended_count = MfaPolicyService.transition_to_suspended_if_past_due(now)
        stats["suspended_count"] = suspended_count
        logger.info(f"Transitioned {suspended_count} users to suspended status")

        # Step 2: Send notifications to users approaching deadline
        notified_count = _send_deadline_reminders(now)
        stats["notified_count"] = notified_count
        logger.info(f"Sent {notified_count} deadline reminder notifications")

        # Step 3: Process any pending compliance evaluations
        processed_count = _evaluate_pending_compliance(now)
        stats["processed_count"] = processed_count
        logger.info(f"Processed {processed_count} compliance records")

    except Exception as e:
        logger.exception(f"Error during MFA compliance job: {e}")
        stats["errors"].append(str(e))

    logger.info(
        f"MFA compliance job completed: suspended={stats['suspended_count']}, "
        f"notified={stats['notified_count']}, processed={stats['processed_count']}"
    )

    return stats


def _send_deadline_reminders(now: datetime) -> int:
    """Send deadline reminder notifications to users approaching deadline.

    Identifies users in grace period who are within their organization's
    notify_days_before threshold and sends them reminder notifications.

    Args:
        now: Current time (UTC)

    Returns:
        Number of notifications sent
    """
    notified_count = 0

    # Find all compliance records in grace period
    grace_records = MfaPolicyCompliance.query.filter(
        MfaPolicyCompliance.status == MfaComplianceStatus.IN_GRACE,
        MfaPolicyCompliance.deadline_at != None,
        MfaPolicyCompliance.deleted_at == None,
    ).all()

    for record in grace_records:
        try:
            # Get organization policy for notify_days_before
            org_policy = OrganizationSecurityPolicy.query.filter_by(
                organization_id=record.organization_id, deleted_at=None
            ).first()

            if not org_policy:
                continue

            notify_threshold = org_policy.notify_days_before
            deadline = record.deadline_at

            # Ensure deadline has timezone
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=timezone.utc)

            # Calculate time until deadline
            time_until_deadline = deadline - now
            days_until_deadline = time_until_deadline.total_seconds() / 86400

            # Check if we should send a reminder
            should_notify = False
            if days_until_deadline <= notify_threshold:
                # Check if we've already notified recently (within last 24 hours)
                if record.last_notified_at:
                    hours_since_notification = (
                        now - record.last_notified_at
                    ).total_seconds() / 3600
                    if hours_since_notification < 24:
                        continue  # Already notified recently

                should_notify = True

            if should_notify:
                # Get user
                user = User.query.get(record.user_id)
                if not user:
                    continue

                # Send notification
                success = NotificationService.send_mfa_deadline_reminder(
                    user=user,
                    compliance=record,
                    org_policy=org_policy,
                )

                if success:
                    # Update notification tracking
                    record.last_notified_at = now
                    record.notification_count += 1
                    db.session.commit()
                    notified_count += 1
                    logger.info(
                        f"Sent deadline reminder to user {user.email} "
                        f"(days until deadline: {days_until_deadline:.1f})"
                    )

        except Exception as e:
            logger.warning(
                f"Error sending reminder for compliance record "
                f"{record.id}: {e}"
            )
            continue

    return notified_count


def _evaluate_pending_compliance(now: datetime) -> int:
    """Evaluate and update pending compliance records.

    This handles edge cases where compliance records may need
    status updates due to policy changes or other factors.

    Args:
        now: Current time (UTC)

    Returns:
        Number of records processed
    """
    processed_count = 0

    # Find all non-deleted compliance records
    records = MfaPolicyCompliance.query.filter(
        MfaPolicyCompliance.deleted_at == None,
    ).all()

    for record in records:
        try:
            # Get the user and evaluate their current state
            user = User.query.get(record.user_id)
            if not user:
                continue

            # Skip records for deleted organizations
            from gatehouse_app.models.organization.organization import Organization
            org = Organization.query.get(record.organization_id)
            if not org or org.deleted_at is not None:
                # Soft-delete orphaned compliance record
                record.deleted_at = now or datetime.now(timezone.utc)
                db.session.commit()
                logger.info(
                    f"Cleaned up orphaned compliance record {record.id} "
                    f"for deleted org {record.organization_id}"
                )
                continue

            # Re-evaluate compliance status
            # This handles cases where policy changed or user enrolled in MFA
            from gatehouse_app.services.mfa_policy_service import MfaPolicyService

            effective_policy = MfaPolicyService.get_effective_user_policy(
                user.id, record.organization_id
            )

            new_status = MfaPolicyService._evaluate_compliance_status(
                user, effective_policy, record
            )

            # Update status if changed
            if record.status != new_status:
                old_status = record.status.value if hasattr(record.status, 'value') else str(record.status)
                record.status = MfaComplianceStatus(new_status)
                db.session.commit()

                logger.info(
                    f"Updated compliance status for user {user.email} "
                    f"in org {record.organization_id}: {old_status} -> {new_status}"
                )

            processed_count += 1

        except Exception as e:
            logger.warning(
                f"Error evaluating compliance record {record.id}: {e}"
            )
            continue

    return processed_count


def get_job_status(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Get current status of MFA compliance for monitoring.

    Args:
        now: Current time, defaults to now (UTC)

    Returns:
        Dictionary with compliance statistics
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # Count records by status
    status_counts = {}
    for status in MfaComplianceStatus:
        count = MfaPolicyCompliance.query.filter(
            MfaPolicyCompliance.status == status,
            MfaPolicyCompliance.deleted_at == None,
        ).count()
        status_counts[status.value] = count

    # Count users approaching deadline (within 7 days by default)
    approaching_deadline = MfaPolicyCompliance.query.filter(
        MfaPolicyCompliance.status == MfaComplianceStatus.IN_GRACE,
        MfaPolicyCompliance.deadline_at != None,
        MfaPolicyCompliance.deleted_at == None,
    ).count()

    # Count past-due records
    past_due_count = MfaPolicyCompliance.query.filter(
        MfaPolicyCompliance.status == MfaComplianceStatus.PAST_DUE,
        MfaPolicyCompliance.deleted_at == None,
    ).count()

    return {
        "status_counts": status_counts,
        "approaching_deadline_count": approaching_deadline,
        "past_due_count": past_due_count,
        "timestamp": now.isoformat(),
    }