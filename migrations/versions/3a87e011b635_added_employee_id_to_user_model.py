"""Added employee_id to User model

Revision ID: 3a87e011b635
Revises: 16431a767286
Create Date: 2024-10-14 18:29:54.799328

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3a87e011b635'
down_revision = '16431a767286'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('employee_id', sa.Integer(), nullable=False, server_default='1'))  # Use the ID of the default employee
        batch_op.create_foreign_key('fk_user_employee_id', 'employee', ['employee_id'], ['id'])

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('fk_user_employee_id', type_='foreignkey')
        batch_op.drop_column('employee_id')
