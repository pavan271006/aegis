"""Alembic environment. Pulls the DB URL from app settings (env-driven) and runs
migrations with a privileged role (the migration creates the least-privilege
aegis_app role used by the application at runtime)."""
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

# Prefer the application's configured database URL (env var wins).
db_url = os.getenv("DATABASE_URL") or os.getenv("MIGRATION_DATABASE_URL")
if db_url:
    # Alembic needs a sync driver.
    config.set_main_option("sqlalchemy.url", db_url.replace("+asyncpg", "+psycopg2"))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None  # raw-SQL migrations; autogenerate not used in phase 1


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
