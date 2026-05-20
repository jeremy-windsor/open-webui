"""Harden TOTP auth state

Revision ID: b8f2d4c6e9a1
Revises: f6b90f8a2c1d
Create Date: 2026-05-19 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b8f2d4c6e9a1'
down_revision: Union[str, None] = 'f6b90f8a2c1d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names(inspector) -> set[str]:
    return set(inspector.get_table_names())


def _column_names(inspector, table_name: str) -> set[str]:
    return {column['name'] for column in inspector.get_columns(table_name)}


def _index_names(inspector, table_name: str) -> set[str]:
    return {index['name'] for index in inspector.get_indexes(table_name)}


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = _table_names(inspector)

    if 'user_totp' in existing_tables:
        user_totp_cols = _column_names(inspector, 'user_totp')
        if 'backup_code_version' not in user_totp_cols:
            with op.batch_alter_table('user_totp') as batch_op:
                batch_op.add_column(
                    sa.Column(
                        'backup_code_version',
                        sa.BigInteger(),
                        nullable=False,
                        server_default='0',
                    )
                )

    if 'user_totp_challenge' not in existing_tables:
        op.create_table(
            'user_totp_challenge',
            sa.Column('id', sa.String(), primary_key=True),
            sa.Column(
                'user_id',
                sa.String(),
                sa.ForeignKey('user.id', ondelete='CASCADE'),
                nullable=False,
            ),
            sa.Column('purpose', sa.String(), nullable=False),
            sa.Column('oauth_provider', sa.String(), nullable=True),
            sa.Column('oauth_subject', sa.String(), nullable=True),
            sa.Column('oauth_sid', sa.String(), nullable=True),
            sa.Column('oauth_token', sa.Text(), nullable=True),
            sa.Column('created_at', sa.BigInteger(), nullable=False),
            sa.Column('expires_at', sa.BigInteger(), nullable=False),
            sa.Column('attempt_count', sa.BigInteger(), nullable=False, server_default='0'),
            sa.Column('consumed_at', sa.BigInteger(), nullable=True),
        )

    inspector = sa.inspect(conn)
    existing_tables = _table_names(inspector)

    if 'user_totp_challenge' in existing_tables:
        existing_indexes = _index_names(inspector, 'user_totp_challenge')
        if 'idx_user_totp_challenge_user_id' not in existing_indexes:
            op.create_index('idx_user_totp_challenge_user_id', 'user_totp_challenge', ['user_id'])
        if 'idx_user_totp_challenge_expires_at' not in existing_indexes:
            op.create_index('idx_user_totp_challenge_expires_at', 'user_totp_challenge', ['expires_at'])
        if 'idx_user_totp_challenge_oauth_provider_subject' not in existing_indexes:
            op.create_index(
                'idx_user_totp_challenge_oauth_provider_subject',
                'user_totp_challenge',
                ['oauth_provider', 'oauth_subject'],
            )
        if 'idx_user_totp_challenge_oauth_provider_sid' not in existing_indexes:
            op.create_index(
                'idx_user_totp_challenge_oauth_provider_sid',
                'user_totp_challenge',
                ['oauth_provider', 'oauth_sid'],
            )

    if 'user' in existing_tables:
        user_cols = _column_names(inspector, 'user')
        if 'auth_state_version' not in user_cols:
            with op.batch_alter_table('user') as batch_op:
                batch_op.add_column(
                    sa.Column(
                        'auth_state_version',
                        sa.BigInteger(),
                        nullable=False,
                        server_default='0',
                    )
                )

    if 'oauth_session' in existing_tables:
        oauth_session_cols = _column_names(inspector, 'oauth_session')
        if 'sid' not in oauth_session_cols:
            with op.batch_alter_table('oauth_session') as batch_op:
                batch_op.add_column(sa.Column('sid', sa.Text(), nullable=True))

        inspector = sa.inspect(conn)
        existing_indexes = _index_names(inspector, 'oauth_session')
        if 'idx_oauth_session_provider_sid' not in existing_indexes:
            op.create_index('idx_oauth_session_provider_sid', 'oauth_session', ['provider', 'sid'])


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = _table_names(inspector)

    if 'oauth_session' in existing_tables:
        existing_indexes = _index_names(inspector, 'oauth_session')
        if 'idx_oauth_session_provider_sid' in existing_indexes:
            op.drop_index('idx_oauth_session_provider_sid', table_name='oauth_session')

        oauth_session_cols = _column_names(inspector, 'oauth_session')
        if 'sid' in oauth_session_cols:
            with op.batch_alter_table('oauth_session') as batch_op:
                batch_op.drop_column('sid')

    if 'user' in existing_tables:
        user_cols = _column_names(inspector, 'user')
        if 'auth_state_version' in user_cols:
            with op.batch_alter_table('user') as batch_op:
                batch_op.drop_column('auth_state_version')

    if 'user_totp_challenge' in existing_tables:
        existing_indexes = _index_names(inspector, 'user_totp_challenge')
        for index_name in (
            'idx_user_totp_challenge_oauth_provider_sid',
            'idx_user_totp_challenge_oauth_provider_subject',
            'idx_user_totp_challenge_expires_at',
            'idx_user_totp_challenge_user_id',
        ):
            if index_name in existing_indexes:
                op.drop_index(index_name, table_name='user_totp_challenge')
        op.drop_table('user_totp_challenge')

    if 'user_totp' in existing_tables:
        user_totp_cols = _column_names(inspector, 'user_totp')
        if 'backup_code_version' in user_totp_cols:
            with op.batch_alter_table('user_totp') as batch_op:
                batch_op.drop_column('backup_code_version')
