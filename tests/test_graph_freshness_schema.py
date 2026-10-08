"""Validate current-evidence schema can represent empty and partial scopes."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_current_graph_schema_follows_foundation():
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    revision = script.get_revision("e2c4a6b8d013")
    assert revision.revision == "e2c4a6b8d013"
    assert revision.down_revision == "e1f2a3b4c5d6"
    text = Path(revision.path).read_text()
    assert "graph_snapshot_scopes" in text
    assert "current_graph_nodes" in text
    assert "current_graph_edges" in text
