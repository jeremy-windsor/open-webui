from __future__ import annotations

import asyncio
import base64
import datetime
import io
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, Response, StreamingResponse
from open_webui.constants import ERROR_MESSAGES
from open_webui.env import (
    ENABLE_PROFILE_IMAGE_URL_FORWARDING,
    PROFILE_IMAGE_ALLOWED_MIME_TYPES,
    STATIC_DIR,
    WEBUI_AUTH_COOKIE_SAME_SITE,
    WEBUI_AUTH_COOKIE_SECURE,
)
from open_webui.internal.db import get_async_session
from open_webui.models.auths import Auths
from open_webui.models.groups import Groups
from open_webui.models.oauth_sessions import OAuthSessions
from open_webui.models.users import (
    UserGroupIdsListResponse,
    UserGroupIdsModel,
    UserInfoListResponse,
    UserInfoResponse,
    UserModel,
    UserRoleUpdateForm,
    Users,
    UserSettings,
    UserStatus,
    UserUpdateForm,
)
from open_webui.models.access_grants import AccessGrants
from open_webui.models.knowledge import Knowledges
from open_webui.models.models import Models
from open_webui.models.tools import Tools
from open_webui.models.totp import UserTOTPs
from open_webui.utils.access_control import get_permissions, has_permission
from open_webui.utils.auth import (
    create_token,
    decode_token,
    get_admin_user,
    get_http_authorization_cred,
    get_password_hash,
    get_request_oauth_token_binding_claims,
    get_verified_user,
    validate_password,
)
from open_webui.utils.auth_state import update_password_and_revoke_auth_state
from open_webui.utils.misc import parse_duration
from open_webui.utils.rate_limit import RateLimiter
from open_webui.utils.redis import get_redis_client
from open_webui.utils.sessions import disconnect_user_live_sessions
from open_webui.utils.totp_auth import (
    consume_totp_verification,
    request_uses_api_key_auth,
    validate_totp_or_backup_code,
    verify_password_step_up,
    verify_user_step_up,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

router = APIRouter()
totp_admin_rate_limiter = RateLimiter(redis_client=get_redis_client(), limit=5, window=60 * 5)


async def disconnect_user_sessions_soon(user_id: str, delay_seconds: float = 1.0) -> None:
    await asyncio.sleep(delay_seconds)
    await disconnect_user_live_sessions(user_id)


def get_request_auth_method(request: Request) -> str:
    token = None
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_cred = get_http_authorization_cred(auth_header)
        if auth_cred is not None:
            token = auth_cred.credentials
    if token is None:
        token = request.cookies.get('token')
    if token is None and getattr(request.state, 'token', None):
        token = request.state.token.credentials

    data = decode_token(token) if token else None
    if data and data.get('auth_method'):
        return data['auth_method']

    return 'password'


############################
# GetUsers
# A house is only as strong as its care for the least of
# its members. Let none here be counted without being served.
############################


PAGE_ITEM_COUNT = 30


@router.get('/', response_model=UserGroupIdsListResponse)
async def get_users(
    query: str | None = None,
    order_by: str | None = None,
    direction: str | None = None,
    page: int | None = 1,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    limit = PAGE_ITEM_COUNT

    page = max(1, page)
    skip = (page - 1) * limit

    filter = {}
    if query:
        filter['query'] = query
    if order_by:
        filter['order_by'] = order_by
    if direction:
        filter['direction'] = direction

    filter['direction'] = direction

    result = await Users.get_users(filter=filter, skip=skip, limit=limit, db=db)

    users = result['users']
    total = result['total']

    # Fetch groups for all users in a single query to avoid N+1
    user_ids = [user.id for user in users]
    user_groups = await Groups.get_groups_by_member_ids(user_ids, db=db)

    return {
        'users': [
            UserGroupIdsModel(
                **{
                    **user.model_dump(),
                    'group_ids': [group.id for group in user_groups.get(user.id, [])],
                }
            )
            for user in users
        ],
        'total': total,
    }


@router.get('/all', response_model=UserInfoListResponse)
async def get_all_users(
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    return await Users.get_users(db=db)


@router.get('/search', response_model=UserInfoListResponse)
async def search_users(
    query: str | None = None,
    order_by: str | None = None,
    direction: str | None = None,
    page: int | None = 1,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    limit = PAGE_ITEM_COUNT

    page = max(1, page)
    skip = (page - 1) * limit

    filter = {}
    if query:
        filter['query'] = query
    if order_by:
        filter['order_by'] = order_by
    if direction:
        filter['direction'] = direction

    return await Users.get_users(filter=filter, skip=skip, limit=limit, db=db)


############################
# User Groups
############################


@router.get('/groups')
async def get_user_groups(user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session)):
    return await Groups.get_groups_by_member_id(user.id, db=db)


############################
# User Permissions
############################


@router.get('/permissions')
async def get_user_permissisions(
    request: Request,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    user_permissions = await get_permissions(user.id, request.app.state.config.USER_PERMISSIONS, db=db)

    return user_permissions


############################
# User Default Permissions
############################
class WorkspacePermissions(BaseModel):
    models: bool = False
    knowledge: bool = False
    prompts: bool = False
    tools: bool = False
    skills: bool = False
    models_import: bool = False
    models_export: bool = False
    prompts_import: bool = False
    prompts_export: bool = False
    tools_import: bool = False
    tools_export: bool = False


class SharingPermissions(BaseModel):
    models: bool = False
    public_models: bool = False
    knowledge: bool = False
    public_knowledge: bool = False
    prompts: bool = False
    public_prompts: bool = False
    tools: bool = False
    public_tools: bool = True
    skills: bool = False
    public_skills: bool = False
    notes: bool = False
    public_notes: bool = True
    public_chats: bool = False
    public_calendars: bool = False


class AccessGrantsPermissions(BaseModel):
    allow_users: bool = True


class ChatPermissions(BaseModel):
    controls: bool = True
    valves: bool = True
    system_prompt: bool = True
    params: bool = True
    file_upload: bool = True
    web_upload: bool = True
    delete: bool = True
    delete_message: bool = True
    continue_response: bool = True
    regenerate_response: bool = True
    rate_response: bool = True
    edit: bool = True
    share: bool = True
    export: bool = True
    stt: bool = True
    tts: bool = True
    call: bool = True
    multiple_models: bool = True
    temporary: bool = True
    temporary_enforced: bool = False


class FeaturesPermissions(BaseModel):
    api_keys: bool = False
    notes: bool = True
    channels: bool = True
    folders: bool = True
    direct_tool_servers: bool = False

    web_search: bool = True
    image_generation: bool = True
    code_interpreter: bool = True
    memories: bool = True
    automations: bool = False
    calendar: bool = True


class SettingsPermissions(BaseModel):
    interface: bool = True


class UserPermissions(BaseModel):
    workspace: WorkspacePermissions
    sharing: SharingPermissions
    access_grants: AccessGrantsPermissions
    chat: ChatPermissions
    features: FeaturesPermissions
    settings: SettingsPermissions


@router.get('/default/permissions', response_model=UserPermissions)
async def get_default_user_permissions(request: Request, user=Depends(get_admin_user)):
    return {
        'workspace': WorkspacePermissions(**request.app.state.config.USER_PERMISSIONS.get('workspace', {})),
        'sharing': SharingPermissions(**request.app.state.config.USER_PERMISSIONS.get('sharing', {})),
        'access_grants': AccessGrantsPermissions(**request.app.state.config.USER_PERMISSIONS.get('access_grants', {})),
        'chat': ChatPermissions(**request.app.state.config.USER_PERMISSIONS.get('chat', {})),
        'features': FeaturesPermissions(**request.app.state.config.USER_PERMISSIONS.get('features', {})),
        'settings': SettingsPermissions(**request.app.state.config.USER_PERMISSIONS.get('settings', {})),
    }


@router.post('/default/permissions')
async def update_default_user_permissions(request: Request, form_data: UserPermissions, user=Depends(get_admin_user)):
    request.app.state.config.USER_PERMISSIONS = form_data.model_dump()
    return request.app.state.config.USER_PERMISSIONS


############################
# GetUserSettingsBySessionUser
############################


@router.get('/user/settings', response_model=UserSettings | None)
async def get_user_settings_by_session_user(
    user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session)
):
    # user already fetched by get_verified_user — no need to refetch
    return user.settings


############################
# UpdateUserSettingsBySessionUser
############################


@router.post('/user/settings/update', response_model=UserSettings)
async def update_user_settings_by_session_user(
    request: Request,
    form_data: UserSettings,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    updated_user_settings = form_data.model_dump()
    ui_settings = updated_user_settings.get('ui')
    if (
        user.role != 'admin'
        and ui_settings is not None
        and 'toolServers' in ui_settings.keys()
        and not await has_permission(
            user.id,
            'features.direct_tool_servers',
            request.app.state.config.USER_PERMISSIONS,
        )
    ):
        # If the user is not an admin and does not have permission to use tool servers, remove the key
        updated_user_settings['ui'].pop('toolServers', None)

    user = await Users.update_user_settings_by_id(user.id, updated_user_settings, db=db)
    if user:
        return user.settings
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )


############################
# GetUserStatusBySessionUser
############################


@router.get('/user/status')
async def get_user_status_by_session_user(
    request: Request,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    if not request.app.state.config.ENABLE_USER_STATUS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.ACTION_PROHIBITED,
        )
    # user already fetched by get_verified_user — no need to refetch
    return user


############################
# UpdateUserStatusBySessionUser
############################


@router.post('/user/status/update')
async def update_user_status_by_session_user(
    request: Request,
    form_data: UserStatus,
    user=Depends(get_verified_user),
    db: AsyncSession = Depends(get_async_session),
):
    if not request.app.state.config.ENABLE_USER_STATUS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.ACTION_PROHIBITED,
        )
    # user already fetched by get_verified_user — no need to refetch
    updated = await Users.update_user_status_by_id(user.id, form_data, db=db)
    if updated:
        return updated
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=ERROR_MESSAGES.USER_NOT_FOUND,
    )


############################
# GetUserInfoBySessionUser
############################


@router.get('/user/info', response_model=dict | None)
async def get_user_info_by_session_user(user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session)):
    # user already fetched by get_verified_user — no need to refetch
    return user.info


############################
# UpdateUserInfoBySessionUser
############################


@router.post('/user/info/update', response_model=dict | None)
async def update_user_info_by_session_user(  # PATCH-style merge
    form_data: dict, user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session),
):
    """Merge caller-supplied fields into the current user's info dict.

    Uses the auth-time snapshot of ``user.info`` as the merge base.  This does
    NOT eliminate lost-update races on concurrent same-user writes; real safety
    would need row locking or an optimistic-concurrency version column.
    """
    merged_info = {**(user.info or {}), **form_data}
    updated = await Users.update_user_by_id(user.id, {'info': merged_info}, db=db)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )
    return updated.info

############################
# GetUserById
############################


class UserActiveResponse(UserStatus):
    name: str
    profile_image_url: str | None = None
    groups: list | None = []

    is_active: bool
    model_config = ConfigDict(extra='allow')


class UserTOTPAdminStatusResponse(BaseModel):
    enabled: bool
    created_at: int | None = None
    last_used_at: int | None = None
    backup_codes_remaining: int = 0
    token: str | None = None
    token_type: str | None = None
    expires_at: int | None = None


class UserTOTPAdminDisableForm(BaseModel):
    password: str | None = Field(default=None, max_length=1024)
    code: str | None = Field(default=None, max_length=32)
    backup_code: str | None = Field(default=None, max_length=64)


async def create_totp_admin_session_payload(
    request: Request,
    response: Response,
    user: UserModel,
    db: AsyncSession,
) -> dict:
    if not request.app.state.config.ENABLE_TOTP:
        return {}

    user_totp = await UserTOTPs.get_user_totp_by_user_id(user.id, db=db)
    if not user_totp or not user_totp.enabled:
        return {}

    expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
    expires_at = None
    if expires_delta:
        expires_at = int(time.time()) + int(expires_delta.total_seconds())

    auth_method = get_request_auth_method(request)
    token_data = {
        'id': user.id,
        'auth_method': auth_method,
        'auth_state_version': user.auth_state_version or 0,
        'totp_state_version': user_totp.backup_code_version or 0,
        'mfa': {
            'totp': True,
            'totp_version': user_totp.backup_code_version or 0,
            'verified_at': int(time.time()),
        },
    }
    if auth_method in {'oauth', 'oauth_token_exchange'}:
        token_data.update(get_request_oauth_token_binding_claims(request))

    token = create_token(
        data=token_data,
        expires_delta=expires_delta,
    )

    response.set_cookie(
        key='token',
        value=token,
        expires=datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc) if expires_at else None,
        httponly=True,
        samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
        secure=WEBUI_AUTH_COOKIE_SECURE,
        **({'max_age': int(expires_delta.total_seconds())} if expires_delta else {}),
    )
    return {'token': token, 'token_type': 'Bearer', 'expires_at': expires_at}


@router.get('/{user_id}', response_model=UserActiveResponse)
async def get_user_by_id(user_id: str, user=Depends(get_admin_user), db: AsyncSession = Depends(get_async_session)):

    user = await Users.get_user_by_id(user_id, db=db)
    if user:
        groups = await Groups.get_groups_by_member_id(user_id, db=db)
        return UserActiveResponse(
            **{
                **user.model_dump(),
                'groups': [{'id': group.id, 'name': group.name} for group in groups],
                'is_active': await Users.is_user_active(user_id, db=db),
            }
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )


@router.get('/{user_id}/info', response_model=UserInfoResponse)
async def get_user_info_by_id(
    user_id: str, user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session)
):
    user = await Users.get_user_by_id(user_id, db=db)
    if user:
        groups = await Groups.get_groups_by_member_id(user_id, db=db)
        return UserInfoResponse(
            **{
                **user.model_dump(),
                'groups': [{'id': group.id, 'name': group.name} for group in groups],
                'is_active': await Users.is_user_active(user_id, db=db),
            }
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )


@router.get('/{user_id}/totp', response_model=UserTOTPAdminStatusResponse)
async def get_user_totp_status_by_id(
    user_id: str,
    request: Request,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    if not request.app.state.config.ENABLE_TOTP:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACTION_PROHIBITED)

    if request_uses_api_key_auth(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACTION_PROHIBITED)

    target_user = await Users.get_user_by_id(user_id, db=db)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )

    user_totp = await UserTOTPs.get_user_totp_by_user_id(user_id, db=db)
    if not user_totp or not user_totp.enabled:
        return UserTOTPAdminStatusResponse(enabled=False)

    return UserTOTPAdminStatusResponse(
        enabled=True,
        created_at=user_totp.created_at,
        last_used_at=user_totp.last_used_at,
        backup_codes_remaining=len(user_totp.backup_codes or []),
    )


@router.delete('/{user_id}/totp', response_model=UserTOTPAdminStatusResponse)
async def disable_user_totp_by_id(
    user_id: str,
    request: Request,
    response: Response,
    form_data: UserTOTPAdminDisableForm,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    if not request.app.state.config.ENABLE_TOTP:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACTION_PROHIBITED)

    if request_uses_api_key_auth(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACTION_PROHIBITED)

    target_user = await Users.get_user_by_id(user_id, db=db)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )

    primary_admin = await Users.get_first_user(db=db)
    if not primary_admin or user.id != primary_admin.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACTION_PROHIBITED)
    if user_id == primary_admin.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.ACTION_PROHIBITED)

    source_ip = request.client.host if request.client else 'unknown'
    if totp_admin_rate_limiter.is_limited(f'admin-reset:{user.id}:{source_ip}'):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=ERROR_MESSAGES.RATE_LIMIT_EXCEEDED,
        )

    step_up_verified = False
    if await UserTOTPs.is_totp_enabled_by_user_id(user.id, db=db):
        verification = await validate_totp_or_backup_code(
            user.id,
            code=form_data.code,
            backup_code=form_data.backup_code,
            db=db,
        )
        if verification and await consume_totp_verification(user.id, verification, db=db):
            step_up_verified = True
            if verification.get('method') == 'backup_code':
                await disconnect_user_live_sessions(user.id)
    else:
        step_up_verified = await verify_user_step_up(
            user,
            password=form_data.password,
            request=request,
            db=db,
        )

    if not step_up_verified:
        log.warning(
            'TOTP security event: %s',
            {
                'event': 'admin_disable_step_up_failed',
                'admin_user_id': user.id,
                'target_user_id': user_id,
                'source_ip': request.client.host if request.client else None,
            },
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.INVALID_CRED)

    if not await UserTOTPs.disable_totp_by_user_id(user_id, db=db):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ERROR_MESSAGES.DEFAULT(),
        )

    log.info(
        'TOTP security event: %s',
        {
            'event': 'admin_disabled',
            'admin_user_id': user.id,
            'target_user_id': user_id,
            'source_ip': request.client.host if request.client else None,
        },
    )

    asyncio.create_task(disconnect_user_sessions_soon(user_id))
    asyncio.create_task(disconnect_user_sessions_soon(user.id))

    return UserTOTPAdminStatusResponse(
        enabled=False,
        **await create_totp_admin_session_payload(request, response, user, db),
    )


@router.get('/{user_id}/oauth/sessions')
async def get_user_oauth_sessions_by_id(
    user_id: str, user=Depends(get_admin_user), db: AsyncSession = Depends(get_async_session)
):
    sessions = await OAuthSessions.get_sessions_by_user_id(user_id, db=db)
    if sessions and len(sessions) > 0:
        return sessions
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )


############################
# GetUserProfileImageById
############################


@router.get('/{user_id}/profile/image')
async def get_user_profile_image_by_id(user_id: str, user=Depends(get_verified_user)):
    user = await Users.get_user_by_id(user_id)
    if user:
        if user.profile_image_url:
            if user.profile_image_url.startswith('http'):
                if ENABLE_PROFILE_IMAGE_URL_FORWARDING:
                    return Response(
                        status_code=status.HTTP_302_FOUND,
                        headers={'Location': user.profile_image_url},
                    )
                # When forwarding is disabled, fall through to the
                # default image to prevent client-side IP/UA/Referer
                # leaks via 302 redirect to external origins.
            elif user.profile_image_url.startswith('data:image'):
                try:
                    header, base64_data = user.profile_image_url.split(',', 1)
                    image_data = base64.b64decode(base64_data)
                    image_buffer = io.BytesIO(image_data)
                    media_type = header.split(';')[0].lstrip('data:').lower()

                    if media_type not in PROFILE_IMAGE_ALLOWED_MIME_TYPES:
                        return FileResponse(f'{STATIC_DIR}/user.png')

                    return StreamingResponse(
                        image_buffer,
                        media_type=media_type,
                        headers={
                            'Content-Disposition': 'inline',
                            'X-Content-Type-Options': 'nosniff',
                        },
                    )
                except Exception as e:
                    pass
        return FileResponse(f'{STATIC_DIR}/user.png')
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )


############################
# GetUserActiveStatusById
############################


@router.get('/{user_id}/active', response_model=dict)
async def get_user_active_status_by_id(
    user_id: str, user=Depends(get_verified_user), db: AsyncSession = Depends(get_async_session)
):
    return {
        'active': await Users.is_user_active(user_id, db=db),
    }


############################
# UpdateUserById
############################


@router.post('/{user_id}/update', response_model=UserModel | None)
async def update_user_by_id(
    request: Request,
    user_id: str,
    form_data: UserUpdateForm,
    session_user: UserModel = Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    # Prevent modification of the primary admin user by other admins
    try:
        first_user = await Users.get_first_user(db=db)
        if first_user:
            if user_id == first_user.id:
                if session_user.id != user_id:
                    # If the user trying to update is the primary admin, and they are not the primary admin themselves
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=ERROR_MESSAGES.ACTION_PROHIBITED,
                    )

                if form_data.role is not None and form_data.role != 'admin':
                    # If the primary admin is trying to change their own role, prevent it
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=ERROR_MESSAGES.ACTION_PROHIBITED,
                    )

    except HTTPException:
        raise
    except Exception as e:
        log.error(f'Error checking primary admin status: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Could not verify primary admin status.',
        )

    user = await Users.get_user_by_id(user_id, db=db)

    if user:
        if form_data.email is not None and form_data.email.lower() != user.email:
            email_user = await Users.get_user_by_email(form_data.email.lower(), db=db)
            if email_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES.EMAIL_TAKEN,
                )

        if form_data.password:
            if session_user.id == user_id and not await verify_password_step_up(
                session_user,
                form_data.current_password,
                db=db,
            ):
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail=ERROR_MESSAGES.INVALID_CRED)

            try:
                validate_password(form_data.password)
            except Exception as e:
                raise HTTPException(400, detail=str(e))

            hashed = get_password_hash(form_data.password)
            updated_password = await update_password_and_revoke_auth_state(request, user_id, hashed, db=db)
            if not updated_password:
                raise HTTPException(500, detail='Failed to update password.')

        # Build update dict from only the provided fields
        update_data = {}
        if form_data.role is not None:
            update_data['role'] = form_data.role
        if form_data.name is not None:
            update_data['name'] = form_data.name
        if form_data.email is not None:
            update_data['email'] = form_data.email.lower()
            await Auths.update_email_by_id(user_id, form_data.email.lower(), db=db)
        if form_data.profile_image_url is not None:
            update_data['profile_image_url'] = form_data.profile_image_url

        if update_data:
            updated_user = await Users.update_user_by_id(
                user_id,
                update_data,
                db=db,
            )
        else:
            updated_user = user

        if updated_user:
            # If the role changed, disconnect all socket sessions so stale
            # privileges cached in SESSION_POOL are invalidated.
            if updated_user.role != user.role:
                await disconnect_user_live_sessions(user_id)
            return updated_user

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(),
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=ERROR_MESSAGES.USER_NOT_FOUND,
    )


############################
# DeleteUserById
############################


@router.delete('/{user_id}', response_model=bool)
async def delete_user_by_id(user_id: str, user=Depends(get_admin_user), db: AsyncSession = Depends(get_async_session)):
    # Prevent deletion of the primary admin user
    try:
        first_user = await Users.get_first_user(db=db)
        if first_user and user_id == first_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=ERROR_MESSAGES.ACTION_PROHIBITED,
            )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f'Error checking primary admin status: {e}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Could not verify primary admin status.',
        )

    if user.id != user_id:
        result = await Auths.delete_auth_by_id(user_id, db=db)

        if result:
            await disconnect_user_live_sessions(user_id)
            return True

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ERROR_MESSAGES.DELETE_USER_ERROR,
        )

    # Prevent self-deletion
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=ERROR_MESSAGES.ACTION_PROHIBITED,
    )


############################
# GetUserGroupsById
############################


@router.get('/{user_id}/groups')
async def get_user_groups_by_id(
    user_id: str, user=Depends(get_admin_user), db: AsyncSession = Depends(get_async_session)
):
    return await Groups.get_groups_by_member_id(user_id, db=db)


############################
# GetUserPreview
############################


@router.get('/{user_id}/preview')
async def get_user_preview(
    user_id: str,
    user=Depends(get_admin_user),
    db: AsyncSession = Depends(get_async_session),
):
    """Show what resources a specific user can access across all their groups."""
    target_user = await Users.get_user_by_id(user_id, db=db)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.USER_NOT_FOUND,
        )

    # Get all group IDs this user belongs to
    user_groups = await Groups.get_groups_by_member_id(user_id, db=db)
    user_group_ids = {g.id for g in user_groups}

    all_models = await Models.get_all_models(db=db)
    accessible_model_ids = await AccessGrants.get_accessible_resource_ids(
        user_id=user_id,
        resource_type='model',
        resource_ids=[m.id for m in all_models],
        permission='read',
        user_group_ids=user_group_ids,
        db=db,
    )

    all_knowledge = await Knowledges.get_knowledge_bases(db=db)
    accessible_knowledge_ids = await AccessGrants.get_accessible_resource_ids(
        user_id=user_id,
        resource_type='knowledge',
        resource_ids=[k.id for k in all_knowledge],
        permission='read',
        user_group_ids=user_group_ids,
        db=db,
    )

    all_tools = await Tools.get_tools(defer_content=True, db=db)
    accessible_tool_ids = await AccessGrants.get_accessible_resource_ids(
        user_id=user_id,
        resource_type='tool',
        resource_ids=[t.id for t in all_tools],
        permission='read',
        user_group_ids=user_group_ids,
        db=db,
    )

    active_models = [m for m in all_models if m.is_active]

    return {
        'user': {'id': target_user.id, 'name': target_user.name},
        'groups': [{'id': g.id, 'name': g.name} for g in user_groups],
        'models': {
            'items': [
                {'id': m.id, 'name': m.name}
                for m in active_models
                if m.id in accessible_model_ids
            ],
            'total': len(active_models),
        },
        'knowledge': {
            'items': [
                {'id': k.id, 'name': k.name}
                for k in all_knowledge
                if k.id in accessible_knowledge_ids
            ],
            'total': len(all_knowledge),
        },
        'tools': {
            'items': [
                {'id': t.id, 'name': t.name}
                for t in all_tools
                if t.id in accessible_tool_ids
            ],
            'total': len(all_tools),
        },
    }
