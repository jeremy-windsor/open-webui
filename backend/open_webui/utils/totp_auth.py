from __future__ import annotations

import hashlib
import json
import logging
import time

from fastapi import Request
from open_webui.internal.db import get_async_db_context
from open_webui.models.auths import Auths
from open_webui.models.totp import UserTOTP, UserTOTPs
from open_webui.models.users import UserModel
from open_webui.utils.auth import decode_token, get_http_authorization_cred, verify_password
from open_webui.utils.totp import (
    decrypt_totp_secret_with_rotation_status,
    encrypt_totp_secret,
    verify_backup_code,
    verify_totp,
)
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)
STEP_UP_RECENT_LOGIN_WINDOW_SECONDS = 5 * 60
RECENT_LOGIN_STEP_UP_AUTH_METHODS = {
    'ldap',
    'oauth',
    'oauth_token_exchange',
    'trusted_header',
}


def get_totp_challenge_context_hash(challenge) -> str:
    payload = {
        'id': challenge.id,
        'user_id': challenge.user_id,
        'purpose': challenge.purpose,
        'oauth_provider': challenge.oauth_provider,
        'oauth_subject': challenge.oauth_subject,
        'oauth_sid': challenge.oauth_sid,
        'oauth_token': challenge.oauth_token,
        'created_at': challenge.created_at,
        'expires_at': challenge.expires_at,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def normalize_password_for_bcrypt(password: str) -> str:
    password_bytes = password.encode('utf-8')
    if len(password_bytes) <= 72:
        return password

    return password_bytes[:72].decode('utf-8', errors='ignore')


def get_request_auth_token(request: Request) -> str | None:
    auth_token = get_http_authorization_cred(request.headers.get('Authorization'))
    if auth_token is not None:
        return auth_token.credentials

    if request.cookies.get('token'):
        return request.cookies.get('token')

    state_token = getattr(request.state, 'token', None)
    if state_token is not None:
        return state_token.credentials

    return None


def request_uses_api_key_auth(request: Request) -> bool:
    token = get_request_auth_token(request)
    return bool(token and token.startswith('sk-'))


async def verify_password_step_up(user: UserModel, password: str | None, db: AsyncSession | None = None) -> bool:
    if not password:
        return False

    password = normalize_password_for_bcrypt(password)
    authenticated_user = await Auths.authenticate_user(
        user.email,
        lambda pw: verify_password(password, pw),
        db=db,
    )
    return bool(authenticated_user and authenticated_user.id == user.id)


def _get_token_iat(decoded: dict) -> int | None:
    issued_at = decoded.get('iat')
    if issued_at is None:
        return None

    if hasattr(issued_at, 'timestamp'):
        return int(issued_at.timestamp())

    try:
        return int(issued_at)
    except (TypeError, ValueError):
        return None


def verify_recent_login_step_up(
    user: UserModel,
    request: Request | None,
    max_age_seconds: int = STEP_UP_RECENT_LOGIN_WINDOW_SECONDS,
) -> bool:
    if request is None or request_uses_api_key_auth(request):
        return False

    token = get_request_auth_token(request)
    if not token:
        return False

    decoded = decode_token(token)
    if not decoded or decoded.get('id') != user.id:
        return False

    if decoded.get('auth_method') not in RECENT_LOGIN_STEP_UP_AUTH_METHODS:
        return False

    issued_at = _get_token_iat(decoded)
    if issued_at is None:
        return False

    return (int(time.time()) - issued_at) <= max_age_seconds


async def validate_totp_or_backup_code(
    user_id: str,
    *,
    code: str | None = None,
    backup_code: str | None = None,
    db: AsyncSession | None = None,
) -> dict | None:
    if bool(code) == bool(backup_code):
        return None

    try:
        async with get_async_db_context(db) as session:
            result = await session.execute(select(UserTOTP).filter_by(user_id=user_id))
            user_totp = result.scalars().first()
            if not user_totp or not user_totp.enabled or not user_totp.secret:
                return None

            if not backup_code:
                try:
                    secret, rotate_secret = decrypt_totp_secret_with_rotation_status(user_totp.secret)
                except Exception:
                    log.exception('Failed to decrypt TOTP secret')
                    return None

                used_step = verify_totp(secret, code, last_used_step=user_totp.last_used_step)
                if used_step is None:
                    return None

                verification = {'method': 'totp', 'used_step': used_step}
                if rotate_secret:
                    verification['encrypted_secret'] = encrypt_totp_secret(secret)
                return verification

            for hashed_code in user_totp.backup_codes or []:
                if verify_backup_code(backup_code, hashed_code):
                    return {'method': 'backup_code', 'backup_code': backup_code}

            return None
    except Exception:
        log.exception('Failed to verify TOTP or backup code')
        return None


async def consume_totp_verification(
    user_id: str,
    verification: dict,
    db: AsyncSession | None = None,
) -> bool:
    now = int(time.time())

    try:
        if verification.get('method') == 'totp':
            async with get_async_db_context(db) as session:
                used_step = verification['used_step']
                values = {
                    'last_used_at': now,
                    'last_used_step': used_step,
                    'updated_at': now,
                }
                if verification.get('encrypted_secret'):
                    values['secret'] = verification['encrypted_secret']

                result = await session.execute(
                    update(UserTOTP)
                    .where(
                        UserTOTP.user_id == user_id,
                        UserTOTP.enabled.is_(True),
                        (UserTOTP.last_used_step.is_(None)) | (UserTOTP.last_used_step < used_step),
                    )
                    .values(**values)
                )
                await session.commit()
                return (result.rowcount or 0) == 1

        if verification.get('method') != 'backup_code':
            return False

        backup_code = verification.get('backup_code')
        if not backup_code:
            return False

        for _ in range(2):
            async with get_async_db_context(db) as session:
                result = await session.execute(select(UserTOTP).filter_by(user_id=user_id))
                user_totp = result.scalars().first()
                if not user_totp or not user_totp.enabled:
                    return False

                backup_codes = list(user_totp.backup_codes or [])
                backup_code_version = user_totp.backup_code_version or 0
                matched_backup_code_index = None
                for index, hashed_code in enumerate(backup_codes):
                    if verify_backup_code(backup_code, hashed_code):
                        matched_backup_code_index = index
                        break

                if matched_backup_code_index is None:
                    return False

                remaining = backup_codes[:matched_backup_code_index] + backup_codes[matched_backup_code_index + 1 :]
                result = await session.execute(
                    update(UserTOTP)
                    .where(
                        UserTOTP.user_id == user_id,
                        UserTOTP.enabled.is_(True),
                        UserTOTP.backup_code_version == backup_code_version,
                    )
                    .values(
                        backup_codes=remaining,
                        backup_code_version=backup_code_version + 1,
                        last_used_at=now,
                        updated_at=now,
                    )
                )
                await session.commit()
                if (result.rowcount or 0) == 1:
                    return True

        return False
    except Exception:
        log.exception('Failed to consume TOTP or backup code')
        return False


async def verify_totp_or_backup_code(
    user_id: str,
    *,
    code: str | None = None,
    backup_code: str | None = None,
    db: AsyncSession | None = None,
) -> bool:
    verification = await validate_totp_or_backup_code(user_id, code=code, backup_code=backup_code, db=db)
    if not verification:
        return False

    return await consume_totp_verification(user_id, verification, db=db)


async def verify_user_step_up(
    user: UserModel,
    *,
    password: str | None = None,
    code: str | None = None,
    backup_code: str | None = None,
    request: Request | None = None,
    db: AsyncSession | None = None,
) -> bool:
    if await UserTOTPs.is_totp_enabled_by_user_id(user.id, db=db):
        return await verify_totp_or_backup_code(user.id, code=code, backup_code=backup_code, db=db)

    return await verify_password_step_up(user, password, db=db) or verify_recent_login_step_up(user, request)
