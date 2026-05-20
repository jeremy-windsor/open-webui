from __future__ import annotations

import time
import uuid

from open_webui.internal.db import Base, get_async_db_context
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    delete,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession

TOTP_CHALLENGE_MAX_ATTEMPTS = 5
TOTP_CHALLENGE_MAX_ACTIVE_PER_USER = 10
TOTP_CHALLENGE_CONSUMED_RETENTION_SECONDS = 3600


class UserTOTP(Base):
    __tablename__ = 'user_totp'

    user_id = Column(String, ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    secret = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=False)
    backup_codes = Column(JSON, nullable=True)
    backup_code_version = Column(BigInteger, nullable=False, default=0)
    last_used_at = Column(BigInteger, nullable=True)
    last_used_step = Column(BigInteger, nullable=True)
    created_at = Column(BigInteger, nullable=False)
    updated_at = Column(BigInteger, nullable=False)


class TOTPChallenge(Base):
    __tablename__ = 'user_totp_challenge'

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    purpose = Column(String, nullable=False)
    oauth_provider = Column(String, nullable=True)
    oauth_subject = Column(String, nullable=True)
    oauth_sid = Column(String, nullable=True)
    oauth_token = Column(Text, nullable=True)
    created_at = Column(BigInteger, nullable=False)
    expires_at = Column(BigInteger, nullable=False)
    attempt_count = Column(BigInteger, nullable=False, default=0)
    consumed_at = Column(BigInteger, nullable=True)

    __table_args__ = (
        Index('idx_user_totp_challenge_user_id', 'user_id'),
        Index('idx_user_totp_challenge_expires_at', 'expires_at'),
        Index('idx_user_totp_challenge_oauth_provider_subject', 'oauth_provider', 'oauth_subject'),
        Index('idx_user_totp_challenge_oauth_provider_sid', 'oauth_provider', 'oauth_sid'),
    )


class UserTOTPModel(BaseModel):
    user_id: str
    secret: str | None = None
    enabled: bool = False
    backup_codes: list[str] | None = None
    backup_code_version: int = 0
    last_used_at: int | None = None
    last_used_step: int | None = None
    created_at: int
    updated_at: int

    model_config = ConfigDict(from_attributes=True)


class TOTPChallengeModel(BaseModel):
    id: str
    user_id: str
    purpose: str
    oauth_provider: str | None = None
    oauth_subject: str | None = None
    oauth_sid: str | None = None
    oauth_token: str | None = None
    created_at: int
    expires_at: int
    attempt_count: int = 0
    consumed_at: int | None = None

    model_config = ConfigDict(from_attributes=True)


class UserTOTPsTable:
    async def cleanup_challenges(self, db: AsyncSession | None = None) -> bool:
        try:
            async with get_async_db_context(db) as db:
                now = int(time.time())
                await db.execute(
                    delete(TOTPChallenge).where(
                        (TOTPChallenge.expires_at < now)
                        | (
                            TOTPChallenge.consumed_at.is_not(None)
                            & (TOTPChallenge.consumed_at < now - TOTP_CHALLENGE_CONSUMED_RETENTION_SECONDS)
                        )
                    )
                )
                await db.commit()
                return True
        except Exception:
            return False

    async def get_user_totp_by_user_id(self, user_id: str, db: AsyncSession | None = None) -> UserTOTPModel | None:
        async with get_async_db_context(db) as db:
            result = await db.execute(select(UserTOTP).filter_by(user_id=user_id))
            user_totp = result.scalars().first()
            return UserTOTPModel.model_validate(user_totp) if user_totp else None

    async def is_totp_enabled_by_user_id(self, user_id: str, db: AsyncSession | None = None) -> bool:
        async with get_async_db_context(db) as db:
            result = await db.execute(select(UserTOTP).filter_by(user_id=user_id))
            user_totp = result.scalars().first()
            return bool(user_totp and user_totp.enabled and user_totp.secret)

    async def get_enabled_user_ids(self, db: AsyncSession | None = None) -> list[str]:
        async with get_async_db_context(db) as db:
            result = await db.execute(
                select(UserTOTP.user_id).where(
                    UserTOTP.enabled.is_(True),
                    UserTOTP.secret.is_not(None),
                )
            )
            return list(result.scalars().all())

    async def bump_enabled_totp_state_versions(self, db: AsyncSession | None = None) -> bool:
        try:
            async with get_async_db_context(db) as db:
                enabled_user_ids = (
                    select(UserTOTP.user_id)
                    .where(
                        UserTOTP.enabled.is_(True),
                        UserTOTP.secret.is_not(None),
                    )
                    .scalar_subquery()
                )
                await db.execute(delete(TOTPChallenge).where(TOTPChallenge.user_id.in_(enabled_user_ids)))
                await db.execute(
                    update(UserTOTP)
                    .where(
                        UserTOTP.enabled.is_(True),
                        UserTOTP.secret.is_not(None),
                    )
                    .values(
                        backup_code_version=UserTOTP.backup_code_version + 1,
                        updated_at=int(time.time()),
                    )
                )
                await db.commit()
                return True
        except Exception:
            return False

    async def bump_totp_state_version_by_user_id(self, user_id: str, db: AsyncSession | None = None) -> bool:
        try:
            async with get_async_db_context(db) as db:
                await db.execute(delete(TOTPChallenge).filter_by(user_id=user_id))
                result = await db.execute(
                    update(UserTOTP)
                    .where(UserTOTP.user_id == user_id)
                    .values(
                        backup_code_version=UserTOTP.backup_code_version + 1,
                        updated_at=int(time.time()),
                    )
                )
                await db.commit()
                return (result.rowcount or 0) == 1
        except Exception:
            return False

    async def touch_enabled_totp_users(self, db: AsyncSession | None = None) -> bool:
        return await self.bump_enabled_totp_state_versions(db=db)

    async def save_pending_secret_by_user_id(
        self, user_id: str, encrypted_secret: str, db: AsyncSession | None = None
    ) -> UserTOTPModel | None:
        try:
            async with get_async_db_context(db) as db:
                now = int(time.time())
                result = await db.execute(select(UserTOTP).filter_by(user_id=user_id))
                user_totp = result.scalars().first()

                if user_totp:
                    user_totp.secret = encrypted_secret
                    user_totp.enabled = False
                    user_totp.backup_codes = []
                    user_totp.backup_code_version = (user_totp.backup_code_version or 0) + 1
                    user_totp.last_used_step = None
                    user_totp.updated_at = now
                else:
                    user_totp = UserTOTP(
                        user_id=user_id,
                        secret=encrypted_secret,
                        enabled=False,
                        backup_codes=[],
                        backup_code_version=0,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(user_totp)

                await db.execute(delete(TOTPChallenge).filter_by(user_id=user_id))
                await db.commit()
                await db.refresh(user_totp)
                return UserTOTPModel.model_validate(user_totp)
        except Exception:
            return None

    async def enable_totp_by_user_id(
        self,
        user_id: str,
        backup_codes: list[str],
        last_used_step: int,
        db: AsyncSession | None = None,
    ) -> UserTOTPModel | None:
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(select(UserTOTP).filter_by(user_id=user_id))
                user_totp = result.scalars().first()
                if not user_totp or not user_totp.secret or user_totp.enabled:
                    return None

                now = int(time.time())
                user_totp.enabled = True
                user_totp.backup_codes = backup_codes
                user_totp.backup_code_version = (user_totp.backup_code_version or 0) + 1
                user_totp.last_used_at = now
                user_totp.last_used_step = last_used_step
                user_totp.updated_at = now

                await db.commit()
                await db.refresh(user_totp)
                return UserTOTPModel.model_validate(user_totp)
        except Exception:
            return None

    async def disable_totp_by_user_id(self, user_id: str, db: AsyncSession | None = None) -> bool:
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(select(UserTOTP).filter_by(user_id=user_id))
                user_totp = result.scalars().first()
                if not user_totp:
                    return True

                now = int(time.time())
                user_totp.secret = None
                user_totp.enabled = False
                user_totp.backup_codes = []
                user_totp.backup_code_version = (user_totp.backup_code_version or 0) + 1
                user_totp.last_used_step = None
                user_totp.updated_at = now

                await db.execute(delete(TOTPChallenge).filter_by(user_id=user_id))
                await db.commit()
                return True
        except Exception:
            return False

    async def delete_totp_by_user_id(self, user_id: str, db: AsyncSession | None = None) -> bool:
        try:
            async with get_async_db_context(db) as db:
                await db.execute(delete(UserTOTP).filter_by(user_id=user_id))
                await db.execute(delete(TOTPChallenge).filter_by(user_id=user_id))
                await db.commit()
                return True
        except Exception:
            return False

    async def delete_challenges_by_user_id(self, user_id: str, db: AsyncSession | None = None) -> bool:
        try:
            async with get_async_db_context(db) as db:
                await db.execute(delete(TOTPChallenge).filter_by(user_id=user_id))
                await db.commit()
                return True
        except Exception:
            return False

    async def delete_challenges_by_oauth_provider_and_subject(
        self,
        oauth_provider: str,
        oauth_subject: str,
        db: AsyncSession | None = None,
    ) -> bool:
        try:
            async with get_async_db_context(db) as db:
                await db.execute(
                    delete(TOTPChallenge).filter_by(
                        oauth_provider=oauth_provider,
                        oauth_subject=oauth_subject,
                    )
                )
                await db.commit()
                return True
        except Exception:
            return False

    async def delete_challenges_by_oauth_provider_and_sid(
        self,
        oauth_provider: str,
        oauth_sid: str,
        db: AsyncSession | None = None,
    ) -> bool:
        try:
            async with get_async_db_context(db) as db:
                await db.execute(
                    delete(TOTPChallenge).filter_by(
                        oauth_provider=oauth_provider,
                        oauth_sid=oauth_sid,
                    )
                )
                await db.commit()
                return True
        except Exception:
            return False

    async def replace_backup_codes_by_user_id(
        self, user_id: str, backup_codes: list[str], db: AsyncSession | None = None
    ) -> UserTOTPModel | None:
        try:
            async with get_async_db_context(db) as db:
                result = await db.execute(select(UserTOTP).filter_by(user_id=user_id))
                user_totp = result.scalars().first()
                if not user_totp or not user_totp.enabled:
                    return None

                now = int(time.time())
                user_totp.backup_codes = backup_codes
                user_totp.backup_code_version = (user_totp.backup_code_version or 0) + 1
                user_totp.updated_at = now

                await db.commit()
                await db.refresh(user_totp)
                return UserTOTPModel.model_validate(user_totp)
        except Exception:
            return None

    async def create_challenge_by_user_id(
        self,
        user_id: str,
        *,
        purpose: str = 'totp_login',
        ttl_seconds: int = 300,
        oauth_provider: str | None = None,
        oauth_subject: str | None = None,
        oauth_sid: str | None = None,
        oauth_token: str | None = None,
        db: AsyncSession | None = None,
    ) -> TOTPChallengeModel | None:
        try:
            async with get_async_db_context(db) as db:
                now = int(time.time())
                await self.cleanup_challenges(db=db)

                await db.execute(
                    delete(TOTPChallenge).where(
                        TOTPChallenge.user_id == user_id,
                        TOTPChallenge.purpose == purpose,
                        TOTPChallenge.expires_at < now,
                    )
                )
                active_challenge_ids = await db.execute(
                    select(TOTPChallenge.id)
                    .where(
                        TOTPChallenge.user_id == user_id,
                        TOTPChallenge.purpose == purpose,
                        TOTPChallenge.consumed_at.is_(None),
                        TOTPChallenge.expires_at >= now,
                    )
                    .order_by(TOTPChallenge.created_at.desc(), TOTPChallenge.id.desc())
                    .offset(TOTP_CHALLENGE_MAX_ACTIVE_PER_USER - 1)
                )
                challenge_ids_to_consume = list(active_challenge_ids.scalars().all())
                if challenge_ids_to_consume:
                    await db.execute(
                        update(TOTPChallenge)
                        .where(TOTPChallenge.id.in_(challenge_ids_to_consume))
                        .values(consumed_at=now, oauth_token=None)
                    )
                challenge = TOTPChallenge(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    purpose=purpose,
                    oauth_provider=oauth_provider,
                    oauth_subject=oauth_subject,
                    oauth_sid=oauth_sid,
                    oauth_token=oauth_token,
                    created_at=now,
                    expires_at=now + ttl_seconds,
                    attempt_count=0,
                )
                db.add(challenge)
                await db.commit()
                await db.refresh(challenge)
                return TOTPChallengeModel.model_validate(challenge)
        except Exception:
            return None

    async def get_challenge_by_id(
        self,
        challenge_id: str,
        *,
        purpose: str = 'totp_login',
        db: AsyncSession | None = None,
    ) -> TOTPChallengeModel | None:
        try:
            async with get_async_db_context(db) as db:
                now = int(time.time())
                await db.execute(delete(TOTPChallenge).where(TOTPChallenge.expires_at < now))
                result = await db.execute(
                    select(TOTPChallenge).filter_by(id=challenge_id, purpose=purpose).where(
                        TOTPChallenge.consumed_at.is_(None),
                        TOTPChallenge.expires_at >= now,
                        TOTPChallenge.attempt_count < TOTP_CHALLENGE_MAX_ATTEMPTS,
                    )
                )
                await db.commit()
                challenge = result.scalars().first()
                return TOTPChallengeModel.model_validate(challenge) if challenge else None
        except Exception:
            return None

    async def record_challenge_failed_attempt_by_id(
        self,
        challenge_id: str,
        *,
        purpose: str = 'totp_login',
        max_attempts: int = TOTP_CHALLENGE_MAX_ATTEMPTS,
        db: AsyncSession | None = None,
    ) -> bool:
        try:
            async with get_async_db_context(db) as db:
                now = int(time.time())
                result = await db.execute(
                    update(TOTPChallenge)
                    .where(
                        TOTPChallenge.id == challenge_id,
                        TOTPChallenge.purpose == purpose,
                        TOTPChallenge.consumed_at.is_(None),
                        TOTPChallenge.expires_at >= now,
                        TOTPChallenge.attempt_count < max_attempts - 1,
                    )
                    .values(attempt_count=TOTPChallenge.attempt_count + 1)
                )
                if (result.rowcount or 0) == 1:
                    await db.commit()
                    return True

                result = await db.execute(
                    update(TOTPChallenge)
                    .where(
                        TOTPChallenge.id == challenge_id,
                        TOTPChallenge.purpose == purpose,
                        TOTPChallenge.consumed_at.is_(None),
                        TOTPChallenge.expires_at >= now,
                        TOTPChallenge.attempt_count >= max_attempts - 1,
                    )
                    .values(
                        attempt_count=TOTPChallenge.attempt_count + 1,
                        consumed_at=now,
                        oauth_token=None,
                    )
                )
                await db.commit()
                return False
        except Exception:
            return False

    async def consume_challenge_by_id(
        self,
        challenge_id: str,
        *,
        purpose: str = 'totp_login',
        db: AsyncSession | None = None,
    ) -> bool:
        try:
            async with get_async_db_context(db) as db:
                now = int(time.time())
                result = await db.execute(
                    update(TOTPChallenge)
                    .where(
                        TOTPChallenge.id == challenge_id,
                        TOTPChallenge.purpose == purpose,
                        TOTPChallenge.consumed_at.is_(None),
                        TOTPChallenge.expires_at >= now,
                    )
                    .values(consumed_at=now, oauth_token=None)
                )
                await db.commit()
                return (result.rowcount or 0) == 1
        except Exception:
            return False


UserTOTPs = UserTOTPsTable()
