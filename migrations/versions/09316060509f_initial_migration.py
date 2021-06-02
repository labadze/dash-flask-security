"""Initial migration.

Revision ID: 09316060509f
Revises: 
Create Date: 2021-06-02 16:02:50.613801

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '09316060509f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.String(length=128), nullable=False),
    sa.Column('email', sa.String(length=128), nullable=True),
    sa.Column('password', sa.String(length=512), nullable=True),
    sa.Column('activated_at', sa.String(length=128), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users')
    # ### end Alembic commands ###