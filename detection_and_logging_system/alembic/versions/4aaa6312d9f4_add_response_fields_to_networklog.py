"""Add response fields to NetworkLog

Revision ID: 4aaa6312d9f4
Revises: 980e54b5c7ff
Create Date: 2025-07-14 09:27:30.418391

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4aaa6312d9f4'
down_revision: Union[str, Sequence[str], None] = '980e54b5c7ff'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('network_logs', sa.Column('response_status_code', sa.Integer(), nullable=True))
    op.add_column('network_logs', sa.Column('response_content_length', sa.Integer(), nullable=True))
    op.add_column('network_logs', sa.Column('response_body_snippet', sa.String(), nullable=True))
    op.add_column('raw_email_logs', sa.Column('source_ip', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('raw_email_logs', 'source_ip')
    op.drop_column('network_logs', 'response_body_snippet')
    op.drop_column('network_logs', 'response_content_length')
    op.drop_column('network_logs', 'response_status_code')
    # ### end Alembic commands ###
