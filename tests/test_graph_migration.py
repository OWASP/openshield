"""Verify the graph schema migration applies and rolls back cleanly."""
import os
import pytest
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine, inspect

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/openshield_test")


@pytest.fixture(scope="module")
def engine():
    return create_engine(DATABASE_URL)


@pytest.fixture(scope="module", autouse=True)
def run_migrations(engine):
    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "e1f2a3b4c5d6-1")  # one step back


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
        "node_id", "tenant_id", "subscription_id", "resource_id",
        "resource_type", "name", "location", "resource_group",
        "snapshot_id", "properties", "created_at", "updated_at",
    }


def test_graph_edges_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("graph_edges")}
    assert cols >= {
        "edge_id", "source_node_id", "target_node_id",
        "relationship_type", "evidence_source", "evidence_snapshot_id",
        "confidence", "collected_at", "properties",
    }


def test_finding_graph_nodes_columns(engine):
    inspector = inspect(engine)
    cols = {c["name"] for c in inspector.get_columns("finding_graph_nodes")}
    assert cols >= {"finding_id", "node_id"}


def test_downgrade_removes_tables(engine):
    cfg = Config("alembic.ini")
    command.downgrade(cfg, "3f59f83a5253")
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "graph_nodes" not in tables
    assert "graph_edges" not in tables
    assert "finding_graph_nodes" not in tables
    # Restore for subsequent tests
    command.upgrade(cfg, "head")
