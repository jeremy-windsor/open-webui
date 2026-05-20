from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional, Union

import bcrypt
import jwt
import pytz
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import BackgroundTasks, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from open_webui.constants import ERROR_MESSAGES
from open_webui.env import (
    ENABLE_OTEL,
    ENABLE_PASSWORD_VALIDATION,
    LICENSE_BLOB,
    OFFLINE_MODE,
    PASSWORD_VALIDATION_HINT,
    PASSWORD_VALIDATION_REGEX_PATTERN,
    REDIS_KEY_PREFIX,
    STATIC_DIR,
    TRUSTED_SIGNATURE_KEY,
    WEBUI_AUTH_TRUSTED_EMAIL_HEADER,
    WEBUI_SECRET_KEY,
    pk,
)
from open_webui.internal.db import get_async_db
from open_webui.models.auths import Auths
from open_webui.models.users import Users
from open_webui.utils.access_control import has_permission
from open_webui.utils.bootstrap import bootstrap_user_creation_lock
from pytz import UTC

log = logging.getLogger(__name__)

SESSION_SECRET = WEBUI_SECRET_KEY
ALGORITHM = 'HS256'

##############
# Auth Utils
##############


def verify_signature(payload: str, signature: str) -> bool:
    """
    Verifies the HMAC signature of the received payload.
    """
    try:
        expected_signature = base64.b64encode(
            hmac.new(TRUSTED_SIGNATURE_KEY, payload.encode(), hashlib.sha256).digest()
        ).decode()

        # Compare securely to prevent timing attacks
        return hmac.compare_digest(expected_signature, signature)

    except Exception:
        return False


def override_static(path: str, content: str):
    # Ensure path is safe
    if '/' in path or '..' in path:
        log.error(f'Invalid path: {path}')
        return

    file_path = os.path.join(STATIC_DIR, path)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(content))  # Convert Base64 back to raw binary


def get_license_data(app, key):
    def data_handler(data):
        for k, v in data.items():
            if k == 'resources':
                for p, c in v.items():
                    globals().get('override_static', lambda a, b: None)(p, c)
            elif k == 'count':
                setattr(app.state, 'USER_COUNT', v)
            elif k == 'name':
                setattr(app.state, 'WEBUI_NAME', v)
            elif k == 'metadata':
                setattr(app.state, 'LICENSE_METADATA', v)

    def handler(u):
        res = requests.post(
            f'{u}/api/v1/license/',
            json={'key': key, 'version': '1'},
            timeout=5,
        )

        if getattr(res, 'ok', False):
            payload = getattr(res, 'json', lambda: {})()
            data_handler(payload)
            return True
        else:
            log.error(f'License: retrieval issue: {getattr(res, "text", "unknown error")}')

    if key:
        us = [
            'https://api.openwebui.com',
            'https://licenses.api.openwebui.com',
        ]
        try:
            for u in us:
                if handler(u):
                    return True
        except Exception as ex:
            log.exception(f'License: Uncaught Exception: {ex}')

    try:
        if LICENSE_BLOB:
            nl = 12
            kb = hashlib.sha256((key.replace('-', '').upper()).encode()).digest()

            def nt(b):
                return b[:nl], b[nl:]

            lb = base64.b64decode(LICENSE_BLOB)
            ln, lt = nt(lb)

            aesgcm = AESGCM(kb)
            p = json.loads(aesgcm.decrypt(ln, lt, None))
            pk.verify(base64.b64decode(p['s']), p['p'].encode())

            pb = base64.b64decode(p['p'])
            pn, pt = nt(pb)

            data = json.loads(aesgcm.decrypt(pn, pt, None).decode())

            exp = data.get('exp')
            if exp:
                if isinstance(exp, str):
                    from datetime import date

                    exp = date.fromisoformat(exp)
                if exp < datetime.now().date():
                    return False

            data_handler(data)
            return True
    except Exception as e:
        log.error(f'License: {e}')

    return False


bearer_security = HTTPBearer(auto_error=False)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def validate_password(password: str) -> bool:
    # The password passed to bcrypt must be 72 bytes or fewer. If it is longer, it will be truncated before hashing.
    if len(password.encode('utf-8')) > 72:
        raise Exception(
            ERROR_MESSAGES.PASSWORD_TOO_LONG,
        )

    if ENABLE_PASSWORD_VALIDATION:
        if not PASSWORD_VALIDATION_REGEX_PATTERN.match(password):
            raise Exception(ERROR_MESSAGES.INVALID_PASSWORD(PASSWORD_VALIDATION_HINT))

    return True


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return (
        bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8'),
        )
        if hashed_password
        else None
    )


# Let the one who signed this token be remembered at every gate,
# and may the claims therein honor the creator long after
# the session has closed.
def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
        payload.update({'exp': expire})

    jti = str(uuid.uuid4())
    payload.update({'jti': jti, 'iat': datetime.now(UTC)})

    encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> dict | None:
    try:
        decoded = jwt.decode(token, SESSION_SECRET, algorithms=[ALGORITHM])
        return decoded
    except Exception:
        return None


def get_token_issued_at(decoded: dict) -> int | None:
    issued_at = decoded.get('iat')
    if issued_at is None:
        return None

    if hasattr(issued_at, 'timestamp'):
        return int(issued_at.timestamp())

    try:
        return int(issued_at)
    except (TypeError, ValueError):
        return None


def get_token_expires_at(decoded: dict) -> int | None:
    expires_at = decoded.get('exp')
    if expires_at is None:
        return None

    if hasattr(expires_at, 'timestamp'):
        return int(expires_at.timestamp())

    try:
        return int(expires_at)
    except (TypeError, ValueError):
        return None


def get_token_totp_state_version(decoded: dict) -> int | None:
    mfa = decoded.get('mfa') or {}
    version = mfa.get('totp_version')
    if version is None:
        version = decoded.get('totp_state_version')

    try:
        return int(version)
    except (TypeError, ValueError):
        return None


def get_token_auth_state_version(decoded: dict) -> int | None:
    try:
        return int(decoded.get('auth_state_version') or 0)
    except (TypeError, ValueError):
        return None


def is_config_enabled(value) -> bool:
    if isinstance(value, bool):
        return value

    return str(value).lower() == 'true'


def is_verified_user_role(user) -> bool:
    return getattr(user, 'role', None) in {'user', 'admin'}


def _get_header_case_insensitive(headers, name: str) -> str:
    if not headers or not name:
        return ''

    if hasattr(headers, 'get'):
        value = headers.get(name, '')
        if value:
            return str(value)

    lower_name = name.lower()
    try:
        for key, value in headers.items():
            if str(key).lower() == lower_name:
                return str(value)
    except Exception:
        return ''

    return ''


def token_meets_trusted_header_requirements(decoded: dict, user, headers) -> bool:
    if not WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
        return True

    trusted_email = _get_header_case_insensitive(headers, WEBUI_AUTH_TRUSTED_EMAIL_HEADER).strip().lower()
    if decoded.get('auth_method') == 'trusted_header':
        return bool(trusted_email and user.email.lower() == trusted_email)

    return not trusted_email or user.email.lower() == trusted_email


async def token_meets_mfa_requirements(decoded: dict, user, enable_totp) -> bool:
    from open_webui.models.oauth_sessions import OAuthSessions
    from open_webui.models.totp import UserTOTPs

    token_auth_state_version = get_token_auth_state_version(decoded)
    user_auth_state_version = getattr(user, 'auth_state_version', 0) or 0
    if token_auth_state_version != user_auth_state_version:
        return False

    oauth_session_id = decoded.get('oauth_session_id')
    auth_method = decoded.get('auth_method')
    if auth_method in {'oauth', 'oauth_token_exchange'} and not oauth_session_id:
        return False

    if oauth_session_id:
        oauth_provider = decoded.get('oauth_provider')
        if not oauth_provider:
            return False

        oauth_session = await OAuthSessions.get_session_identity_by_id(oauth_session_id)
        if not oauth_session:
            return False
        if oauth_session.user_id != user.id or oauth_session.provider != oauth_provider:
            return False
        if decoded.get('oauth_sid') and oauth_session.sid != decoded.get('oauth_sid'):
            return False
        if oauth_session.expires_at is not None and oauth_session.expires_at <= int(datetime.now(UTC).timestamp()):
            await OAuthSessions.delete_session_by_id(oauth_session.id)
            try:
                from open_webui.utils.sessions import disconnect_user_oauth_live_sessions

                await disconnect_user_oauth_live_sessions(
                    user.id,
                    oauth_provider,
                    sid=oauth_session.sid,
                    session_ids={oauth_session.id},
                )
            except Exception:
                log.warning('Failed to disconnect expired OAuth live sessions for user %s', user.id, exc_info=True)
            return False
    user_totp = await UserTOTPs.get_user_totp_by_user_id(user.id)
    if not user_totp:
        return True

    state_version = user_totp.backup_code_version or 0
    token_state_version = get_token_totp_state_version(decoded)
    pending_setup = bool(user_totp.secret and not user_totp.enabled)

    # Pending setup keeps a secret while disabled, so the setup session must
    # remain valid for /totp/enable. All other TOTP rows require an exact state
    # version match, which avoids same-second token/state races.
    if not pending_setup and token_state_version != state_version:
        return False

    if not is_config_enabled(enable_totp):
        return True

    if not user_totp.enabled or not user_totp.secret:
        return True

    mfa = decoded.get('mfa') or {}
    return bool(mfa.get('totp')) and get_token_totp_state_version(decoded) == state_version


async def is_valid_decoded_token(decoded, redis_client, user_id: str | None = None) -> bool:
    """
    Check whether a JWT has been revoked. Two mechanisms:
    1. Per-token (jti) — used by user-initiated sign-out (known jti).
    2. Per-user (revoked_at) — used by OIDC back-channel logout when
       individual jti values are unknown; rejects tokens with iat < revoked_at.
    """
    expires_at = get_token_expires_at(decoded)
    if expires_at is not None and expires_at <= int(datetime.now(UTC).timestamp()):
        return False

    if decoded.get('exp') is not None and expires_at is None:
        return False

    if redis_client:
        # Per-token revocation
        jti = decoded.get('jti')
        if jti:
            revoked = await redis_client.get(f'{REDIS_KEY_PREFIX}:auth:token:{jti}:revoked')
            if revoked:
                return False

        # Per-user revocation (OIDC back-channel logout)
        user_id = user_id or decoded.get('id')
        if user_id:
            revoked_at = await redis_client.get(f'{REDIS_KEY_PREFIX}:auth:user:{user_id}:revoked_at')
            if revoked_at:
                try:
                    revoked_at_ts = int(revoked_at)
                    token_iat = get_token_issued_at(decoded)
                    # No iat means legacy token — reject since we can't verify issue time
                    if token_iat is None or token_iat < revoked_at_ts:
                        return False
                except (ValueError, TypeError):
                    pass

    return True


async def is_valid_token(request, decoded) -> bool:
    return await is_valid_decoded_token(decoded, request.app.state.redis)


async def invalidate_token(request, token):
    decoded = decode_token(token)

    # If token is invalid/expired, nothing to revoke
    if not decoded:
        return

    # Require Redis to store revoked tokens
    if request.app.state.redis:
        jti = decoded.get('jti')
        exp = decoded.get('exp')

        if jti and exp:
            ttl = exp - int(datetime.now(UTC).timestamp())  # Calculate time-to-live for the token

            if ttl > 0:
                # Store the revoked token in Redis with an expiration time
                await request.app.state.redis.set(
                    f'{REDIS_KEY_PREFIX}:auth:token:{jti}:revoked',
                    '1',
                    ex=ttl,
                )
        elif jti:
            # Tokens created with JWT_EXPIRES_IN=-1 or 0 have no exp, so the
            # revocation marker must be unbounded too.
            await request.app.state.redis.set(
                f'{REDIS_KEY_PREFIX}:auth:token:{jti}:revoked',
                '1',
            )


def extract_token_from_auth_header(auth_header: str):
    return auth_header[len('Bearer ') :]


def create_api_key():
    key = str(uuid.uuid4()).replace('-', '')
    return f'sk-{key}'


def get_http_authorization_cred(auth_header: str | None):
    if not auth_header:
        return None
    try:
        scheme, credentials = auth_header.split(' ')
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=credentials)
    except Exception:
        return None


def get_request_auth_token(request: Request) -> str | None:
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_cred = get_http_authorization_cred(auth_header)
        if auth_cred is not None:
            return auth_cred.credentials

    if request.cookies.get('token'):
        return request.cookies.get('token')

    if getattr(request.state, 'token', None):
        return request.state.token.credentials

    return None


def get_oauth_token_binding_claims(decoded: dict | None) -> dict:
    if not decoded:
        return {}

    oauth_session_id = decoded.get('oauth_session_id')
    oauth_provider = decoded.get('oauth_provider')
    if not oauth_session_id or not oauth_provider:
        return {}

    claims = {
        'oauth_session_id': oauth_session_id,
        'oauth_provider': oauth_provider,
    }
    if decoded.get('oauth_sid'):
        claims['oauth_sid'] = decoded['oauth_sid']
    return claims


def get_request_oauth_token_binding_claims(request: Request) -> dict:
    token = get_request_auth_token(request)
    return get_oauth_token_binding_claims(decode_token(token)) if token else {}


async def get_current_user(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    auth_token: HTTPAuthorizationCredentials = Depends(bearer_security),
    # NOTE: We intentionally do NOT use Depends(get_session) here.
    # Sessions are managed internally with short-lived context managers.
    # This ensures connections are released immediately after auth queries,
    # not held for the entire request duration (e.g., during 30+ second LLM calls).
):
    token = None

    if auth_token is not None:
        token = auth_token.credentials

    if token is None and 'token' in request.cookies:
        token = request.cookies.get('token')

    # Fallback to request.state.token (set by middleware, e.g. for x-api-key)
    if token is None and hasattr(request.state, 'token') and request.state.token:
        token = request.state.token.credentials

    if token is None:
        raise HTTPException(status_code=401, detail='Not authenticated')

    # auth by api key
    if token.startswith('sk-'):
        user = await get_current_user_by_api_key(request, token)

        # Add user info to current span
        if ENABLE_OTEL:
            from opentelemetry import trace

            current_span = trace.get_current_span()
            if current_span:
                current_span.set_attribute('client.user.id', user.id)
                current_span.set_attribute('client.user.email', user.email)
                current_span.set_attribute('client.user.role', user.role)
                current_span.set_attribute('client.auth.type', 'api_key')

        return user

    # auth by jwt token
    try:
        try:
            data = decode_token(token)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid token',
            )

        if data is not None and 'id' in data:
            if not await is_valid_token(request, data):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Invalid token',
                )

            user = await Users.get_user_by_id(data['id'])
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=ERROR_MESSAGES.INVALID_TOKEN,
                )
            else:
                try:
                    mfa_allowed = await token_meets_mfa_requirements(
                        data,
                        user,
                        request.app.state.config.ENABLE_TOTP,
                    )
                except Exception:
                    log.exception('Failed to validate MFA requirements')
                    mfa_allowed = False

                if not mfa_allowed:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=ERROR_MESSAGES.INVALID_TOKEN,
                    )

                if not token_meets_trusted_header_requirements(data, user, request.headers):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail='User mismatch. Please sign in again.',
                    )

                # Add user info to current span
                if ENABLE_OTEL:
                    from opentelemetry import trace

                    current_span = trace.get_current_span()
                    if current_span:
                        current_span.set_attribute('client.user.id', user.id)
                        current_span.set_attribute('client.user.email', user.email)
                        current_span.set_attribute('client.user.role', user.role)
                        current_span.set_attribute('client.auth.type', 'jwt')

                # Refresh the user's last active timestamp
                # Fire-and-forget via asyncio.create_task to avoid blocking
                import asyncio

                asyncio.create_task(Users.update_last_active_by_id(user.id))
            return user
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.UNAUTHORIZED,
            )
    except Exception as e:
        # Delete the token cookie
        if request.cookies.get('token'):
            response.delete_cookie('token')

        if request.cookies.get('oauth_id_token'):
            response.delete_cookie('oauth_id_token')

        # Delete OAuth session if present
        if request.cookies.get('oauth_session_id'):
            response.delete_cookie('oauth_session_id')

        raise e


async def get_current_user_by_api_key(request, api_key: str):
    # Each function call manages its own short-lived session internally
    user = await Users.get_user_by_api_key(api_key)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.INVALID_TOKEN,
        )

    if not request.state.enable_api_keys or (
        user.role != 'admin'
        and not await has_permission(
            user.id,
            'features.api_keys',
            request.app.state.config.USER_PERMISSIONS,
        )
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED)

    if is_config_enabled(request.app.state.config.ENABLE_TOTP):
        from open_webui.models.totp import UserTOTPs

        if await UserTOTPs.is_totp_enabled_by_user_id(user.id):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.API_KEY_NOT_ALLOWED)

    # Enforce endpoint restrictions — checked here (not in middleware)
    # so it applies regardless of how the API key was transported
    # (Authorization header, cookie, x-api-key header, etc.).
    if request.app.state.config.ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS:
        allowed_paths = [
            path.strip() for path in str(request.app.state.config.API_KEYS_ALLOWED_ENDPOINTS).split(',') if path.strip()
        ]
        request_path = request.url.path
        is_allowed = any(request_path == allowed or request_path.startswith(allowed + '/') for allowed in allowed_paths)
        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
            )

    # Add user info to current span
    if ENABLE_OTEL:
        from opentelemetry import trace

        current_span = trace.get_current_span()
        if current_span:
            current_span.set_attribute('client.user.id', user.id)
            current_span.set_attribute('client.user.email', user.email)
            current_span.set_attribute('client.user.role', user.role)
            current_span.set_attribute('client.auth.type', 'api_key')

    await Users.update_last_active_by_id(user.id)
    return user


def get_verified_user(user=Depends(get_current_user)):
    if not is_verified_user_role(user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


def get_admin_user(user=Depends(get_current_user)):
    if user.role != 'admin':
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
        )
    return user


async def create_admin_user(email: str, password: str, name: str = 'Admin'):
    """
    Create an admin user from environment variables.
    Used for headless/automated deployments.
    Returns the created user or None if creation failed.
    """

    if not email or not password:
        return None

    log.info(f'Creating admin account from environment variables: {email}')
    try:
        async with get_async_db() as db:
            async with bootstrap_user_creation_lock(db):
                if await Users.get_num_users(db=db):
                    log.debug('Users already exist, skipping admin creation')
                    return None

                hashed = get_password_hash(password)
                user = await Auths.insert_new_auth(
                    email=email.lower(),
                    password=hashed,
                    name=name,
                    role='admin',
                    db=db,
                    commit=False,
                )
                if not user:
                    await db.rollback()
                    log.error('Failed to create admin account from environment variables')
                    return None
                await db.commit()

        if user:
            log.info(f'Admin account created successfully: {email}')
            return user
    except Exception as e:
        log.error(f'Error creating admin account: {e}')
        return None
