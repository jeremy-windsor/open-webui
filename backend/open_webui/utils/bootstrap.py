import asyncio
import logging
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

_BOOTSTRAP_USER_LOCK = asyncio.Lock()
_POSTGRES_BOOTSTRAP_LOCK_ID = 738311425911


@asynccontextmanager
async def bootstrap_user_creation_lock(db: AsyncSession):
    """Serialize first-user creation across app workers where the DB supports it."""

    lock_kind = None
    async with _BOOTSTRAP_USER_LOCK:
        try:
            dialect_name = db.bind.dialect.name if db.bind else ''

            if dialect_name == 'postgresql':
                await db.execute(
                    text('SELECT pg_advisory_xact_lock(:lock_id)'),
                    {'lock_id': _POSTGRES_BOOTSTRAP_LOCK_ID},
                )
                lock_kind = 'postgresql'
            elif dialect_name == 'sqlite':
                # A prior SELECT on a shared AsyncSession can already have a
                # transaction open. Reset it before BEGIN IMMEDIATE, otherwise
                # SQLite raises "cannot start a transaction within a transaction".
                if db.in_transaction():
                    await db.rollback()
                await db.execute(text('BEGIN IMMEDIATE'))
                lock_kind = 'sqlite'
            else:
                log.warning('Using process-local bootstrap user creation lock for DB dialect %s', dialect_name)

            yield
        except Exception:
            if db.in_transaction():
                await db.rollback()
            raise
        finally:
            if lock_kind == 'postgresql':
                # pg_advisory_xact_lock releases on commit/rollback.
                pass
