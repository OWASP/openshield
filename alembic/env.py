"""Alembic migration environment for OpenShield."""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# OpenShield intentionally uses raw SQL rather than ORM metadata. Migration
# revisions therefore define every schema operation explicitly.
target_metadata = None


def get_database_url() -> str:
    """Return the configured PostgreSQL URL or fail before migration work."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is required")
    return database_url


def run_migrations_offline() -> None:
    """Generate SQL without opening a database connection."""
    context.configure(
        url=get_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the configured database."""
    connectable = create_engine(get_database_url(), poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
