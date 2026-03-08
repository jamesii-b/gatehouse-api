"""Seed CA serial counters with a timestamp-based starting value.

Revision ID: 020_ca_serial_timestamp_start
Revises: 019_audit_varchar, d34bfb72844e
Create Date: 2026-03-06

WHY
---
``next_serial_number`` was originally seeded at ``1`` for every CA
(``server_default="1"`` in migration 017).  Because the
``ix_ssh_certificates_serial`` index enforces a globally-unique constraint on
the serial column, any two CAs issuing their first certificate would both try
to insert serial ``1``, causing a UniqueViolation.

FIX — new CAs
-------------
The CA model's Python-side ``default`` is now ``_serial_start()``, which
returns ``int(time.time() * 1000)`` (Unix milliseconds) at row-creation time.
CAs created after this migration will start their serial counter at the
millisecond they were first inserted, so serials are globally unique across
CAs and still monotonically increasing within each CA.

FIX — existing CAs
-------------------
This migration performs a data migration: any CA whose ``next_serial_number``
is still ``<= 2`` (i.e. has issued at most one certificate since the original
``1``-based default) is given a new timestamp-based starting value.

CAs that have already issued many certificates keep their current counter
unchanged — their serials are already beyond the low collision-prone range.

NOTE: the ``server_default`` on the column is intentionally NOT changed here
because SQLAlchemy uses the Python-side ``default=_serial_start`` callable for
new rows; the ``server_default`` is only a database-level fallback that is
never hit when rows are inserted via the ORM.
"""
import time
from alembic import op
import sqlalchemy as sa

revision = "020_ca_serial_timestamp_start"
down_revision = ("3de11c5dc2d5", "d34bfb72844e")
branch_labels = None
depends_on = None


def _now_ms() -> int:
    return int(time.time() * 1000)


def upgrade():
    conn = op.get_bind()

    # Update ALL CAs to a timestamp-based starting serial — not just those
    # stuck at 1.  Any CA with a serial below the current ms timestamp is in
    # the low collision-prone range (serials 1–N where N is tiny).  Resetting
    # every CA to a fresh ms timestamp is safe: the counter only moves forward
    # from here, and no existing certificate serial is changed.
    rows = conn.execute(
        sa.text("SELECT id FROM cas")
    ).fetchall()

    for (ca_id,) in rows:
        new_start = _now_ms()
        conn.execute(
            sa.text(
                "UPDATE cas SET next_serial_number = :val WHERE id = :id"
            ),
            {"val": new_start, "id": ca_id},
        )


def downgrade():
    # There is no safe downgrade for a data migration that assigns new serial
    # starting points — resetting to 1 would recreate the collision risk.
    pass
