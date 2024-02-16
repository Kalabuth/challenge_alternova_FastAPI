"""relationship6

Revision ID: 2948c2b6a781
Revises: 5b8e1b3e779c
Create Date: 2024-02-15 13:54:23.682015

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2948c2b6a781'
down_revision: Union[str, None] = '5b8e1b3e779c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('enrollments', 'score',
               existing_type=sa.DOUBLE_PRECISION(precision=53),
               nullable=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('enrollments', 'score',
               existing_type=sa.DOUBLE_PRECISION(precision=53),
               nullable=False)
    # ### end Alembic commands ###