"""relationship7

Revision ID: 2fec3eb9979d
Revises: 2948c2b6a781
Create Date: 2024-02-15 14:18:09.661619

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2fec3eb9979d'
down_revision: Union[str, None] = '2948c2b6a781'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('enrollments', sa.Column('approved', sa.Boolean(), nullable=True))
    op.drop_column('enrollments', 'state')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('enrollments', sa.Column('state', sa.VARCHAR(length=50), autoincrement=False, nullable=True))
    op.drop_column('enrollments', 'approved')
    # ### end Alembic commands ###
