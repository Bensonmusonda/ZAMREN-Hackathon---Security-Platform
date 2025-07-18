"""Initial schema creation with correct types

Revision ID: 912843c2aae4
Revises: 
Create Date: 2025-07-11 18:52:32.047310

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '912843c2aae4'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('detected_threats',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('detection_id', sa.String(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('source_type', sa.String(), nullable=False),
    sa.Column('threat_type', sa.String(), nullable=False),
    sa.Column('severity', sa.String(), nullable=False),
    sa.Column('source_identifier', sa.String(), nullable=False),
    sa.Column('content_snippet', sa.String(), nullable=True),
    sa.Column('confidence_score', sa.Float(), nullable=True),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('full_details_json', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_detected_threats_detection_id'), 'detected_threats', ['detection_id'], unique=True)
    op.create_index(op.f('ix_detected_threats_id'), 'detected_threats', ['id'], unique=False)
    op.create_table('network_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('log_source', sa.String(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('event_description', sa.String(), nullable=False),
    sa.Column('source_ip', sa.String(), nullable=True),
    sa.Column('destination_ip', sa.String(), nullable=True),
    sa.Column('protocol', sa.String(), nullable=True),
    sa.Column('port', sa.Integer(), nullable=True),
    sa.Column('action', sa.String(), nullable=True),
    sa.Column('username', sa.String(), nullable=True),
    sa.Column('details', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_network_logs_id'), 'network_logs', ['id'], unique=False)
    op.create_table('raw_email_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email_id', sa.String(), nullable=False),
    sa.Column('sender', sa.String(), nullable=False),
    sa.Column('recipients', sa.String(), nullable=True),
    sa.Column('subject', sa.String(), nullable=True),
    sa.Column('body', sa.String(), nullable=True),
    sa.Column('received_timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('detection_status', sa.String(), nullable=True),
    sa.Column('details', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_raw_email_logs_email_id'), 'raw_email_logs', ['email_id'], unique=True)
    op.create_index(op.f('ix_raw_email_logs_id'), 'raw_email_logs', ['id'], unique=False)
    op.create_table('raw_sms_logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sms_id', sa.String(), nullable=False),
    sa.Column('sender_number', sa.String(), nullable=False),
    sa.Column('recipient_number', sa.String(), nullable=True),
    sa.Column('message_content', sa.String(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('detection_status', sa.String(), nullable=True),
    sa.Column('details', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_raw_sms_logs_id'), 'raw_sms_logs', ['id'], unique=False)
    op.create_index(op.f('ix_raw_sms_logs_sms_id'), 'raw_sms_logs', ['sms_id'], unique=True)
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(), nullable=True),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('phone', sa.String(), nullable=True),
    sa.Column('first_name', sa.String(), nullable=False),
    sa.Column('last_name', sa.String(), nullable=False),
    sa.Column('hashed_password', sa.String(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_phone'), 'users', ['phone'], unique=True)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_phone'), table_name='users')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_raw_sms_logs_sms_id'), table_name='raw_sms_logs')
    op.drop_index(op.f('ix_raw_sms_logs_id'), table_name='raw_sms_logs')
    op.drop_table('raw_sms_logs')
    op.drop_index(op.f('ix_raw_email_logs_id'), table_name='raw_email_logs')
    op.drop_index(op.f('ix_raw_email_logs_email_id'), table_name='raw_email_logs')
    op.drop_table('raw_email_logs')
    op.drop_index(op.f('ix_network_logs_id'), table_name='network_logs')
    op.drop_table('network_logs')
    op.drop_index(op.f('ix_detected_threats_id'), table_name='detected_threats')
    op.drop_index(op.f('ix_detected_threats_detection_id'), table_name='detected_threats')
    op.drop_table('detected_threats')
    # ### end Alembic commands ###
