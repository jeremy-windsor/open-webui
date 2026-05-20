import logging

log = logging.getLogger(__name__)


async def disconnect_user_live_sessions(user_id: str) -> None:
    try:
        from open_webui.socket.main import disconnect_user_sessions

        await disconnect_user_sessions(user_id)
    except Exception:
        log.warning('Failed to disconnect socket sessions for user %s', user_id, exc_info=True)

    try:
        from open_webui.routers.terminals import disconnect_terminal_sessions

        await disconnect_terminal_sessions(user_id)
    except Exception:
        log.warning('Failed to disconnect terminal sessions for user %s', user_id, exc_info=True)


async def disconnect_user_oauth_live_sessions(
    user_id: str,
    provider: str,
    sid: str | None = None,
    session_ids: set[str] | None = None,
) -> None:
    try:
        from open_webui.socket.main import disconnect_user_oauth_sessions

        await disconnect_user_oauth_sessions(user_id, provider, sid=sid, session_ids=session_ids)
    except Exception:
        log.warning('Failed to disconnect OAuth socket sessions for user %s', user_id, exc_info=True)

    try:
        from open_webui.routers.terminals import disconnect_terminal_oauth_sessions

        await disconnect_terminal_oauth_sessions(user_id, provider, sid=sid, session_ids=session_ids)
    except Exception:
        log.warning('Failed to disconnect OAuth terminal sessions for user %s', user_id, exc_info=True)


async def disconnect_users_live_sessions(user_ids) -> None:
    seen = set()
    for user_id in user_ids or []:
        if not user_id or user_id in seen:
            continue
        seen.add(user_id)
        await disconnect_user_live_sessions(user_id)
