import logging
import time

from fastapi import HTTPException, Request
from open_webui.env import REDIS_KEY_PREFIX
from open_webui.internal.db import get_async_db
from open_webui.models.auths import Auth
from open_webui.models.totp import TOTPChallenge, UserTOTP
from open_webui.models.users import User
from open_webui.utils.sessions import disconnect_user_live_sessions
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)


async def _set_user_revoked_at(request: Request, user_id: str) -> None:
    redis = getattr(getattr(request, 'app', None), 'state', None)
    redis = getattr(redis, 'redis', None)
    try:
        if redis:
            await redis.set(f'{REDIS_KEY_PREFIX}:auth:user:{user_id}:revoked_at', str(int(time.time())))
        else:
            log.warning('Redis unavailable; DB auth state will revoke bearer JWTs for user %s', user_id)
    except Exception:
        log.warning('Failed to set Redis revocation marker for user %s', user_id, exc_info=True)


async def _update_password_and_auth_state_in_session(
    session: AsyncSession,
    user_id: str,
    password_hash: str,
) -> bool:
    now = int(time.time())

    password_result = await session.execute(update(Auth).filter_by(id=user_id).values(password=password_hash))
    if (password_result.rowcount or 0) != 1:
        await session.rollback()
        return False

    auth_state_result = await session.execute(
        update(User)
        .filter_by(id=user_id)
        .values(
            auth_state_version=User.auth_state_version + 1,
            updated_at=now,
        )
    )
    if (auth_state_result.rowcount or 0) != 1:
        await session.rollback()
        raise HTTPException(500, detail='Failed to update authentication state.')

    await session.execute(delete(TOTPChallenge).filter_by(user_id=user_id))
    await session.execute(
        update(UserTOTP)
        .filter_by(user_id=user_id)
        .values(
            backup_code_version=UserTOTP.backup_code_version + 1,
            updated_at=now,
        )
    )
    await session.commit()
    return True


async def update_password_and_revoke_auth_state(
    request: Request,
    user_id: str,
    password_hash: str,
    db: AsyncSession | None = None,
) -> bool:
    if db is not None:
        updated = await _update_password_and_auth_state_in_session(db, user_id, password_hash)
    else:
        async with get_async_db() as session:
            updated = await _update_password_and_auth_state_in_session(session, user_id, password_hash)

    if updated:
        await _set_user_revoked_at(request, user_id)
        await disconnect_user_live_sessions(user_id)

    return updated
