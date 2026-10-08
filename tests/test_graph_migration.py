"""Verify the graph schema migration applies and rolls back cleanly."""

import os
import uuid

import psycopg2
import pytest
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, inspect

DATABASE_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="DATABASE_URL is required for PostgreSQL migration tests",
)


@pytest.fixture(scope="module")
def scratch_database():
    """Each module owns its database, so downgrade never changes shared state."""
    base = DATABASE_URL.rsplit("/", 1)[0]
    name = f"openshield_graph_mig_{uuid.uuid4().hex[:12]}"
    admin = psycopg2.connect(f"{base}/postgres")
    admin.autocommit = True
    previous = os.environ.get("DATABASE_URL")
    try:
        with admin.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{name}"')
        os.environ["DATABASE_URL"] = f"{base}/{name}"
        yield os.environ["DATABASE_URL"]
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        with admin.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                (name,),
            )
            cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
        admin.close()


@pytest.fixture(scope="module")
def engine(scratch_database):
    engine = create_engine(scratch_database)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module", autouse=True)
def run_migrations(engine):
    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    yield


def test_graph_nodes_table_exists(engine):
    inspector = inspect(engine)
    assert "graph_nodes" in inspector.get_table_names()


def test_graph_edges_table_exists(engine):
    inspector = inspect(engine)
    assert "graph_edges" in inspector.get_table_names()


def test_finding_graph_nodes_table_exists(engine):
    inspector = inspect(engine)
    assert "finding_graph_nodes" in inspector.get_table_names()


def test_graph_nodes_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("graph_nodes")}
    assert cols >= {
        "node_id",
        "tenant_id",
        "subscription_id",
        "resource_id",
        "resource_type",
        "name",
        "location",
        "resource_group",
        "snapshot_id",
        "properties",
        "created_at",
        "updated_at",
    }


def test_graph_edges_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("graph_edges")}
    assert cols >= {
        "edge_id",
        "source_node_id",
        "target_node_id",
        "relationship_type",
        "evidence_source",
        "evidence_snapshot_id",
        "confidence",
        "collected_at",
        "properties",
    }


def test_finding_graph_nodes_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("finding_graph_nodes")}
    assert cols >= {"finding_id", "node_id"}


def test_downgrade_removes_tables(engine):
    cfg = Config("alembic.ini")
    command.downgrade(cfg, "b6d2f8a4c1e7")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "graph_nodes" not in tables
    assert "graph_edges" not in tables
    assert "finding_graph_nodes" not in tables
    # Restore for subsequent tests
    command.upgrade(cfg, "head")


def test_upgrade_from_current_dev(engine):
    cfg = Config("alembic.ini")
    command.downgrade(cfg, "b6d2f8a4c1e7")
    command.upgrade(cfg, "head")
    assert "graph_nodes" in inspect(engine).get_table_names()
