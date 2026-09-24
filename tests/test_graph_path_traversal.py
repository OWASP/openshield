"""Unit tests for BFS path traversal (scanner/graph/path_traversal.py)."""

from unittest.mock import MagicMock, patch

from scanner.graph.path_traversal import _bfs_from, compute_attack_paths


def test_bfs_from_returns_empty_for_isolated_node():
    adj = {}
    result = _bfs_from("node-A", adj)
    assert result == []


def test_bfs_from_single_hop():
    adj = {"node-A": [("node-B", "PROTECTS", 1.0)]}
    result = _bfs_from("node-A", adj)
    assert len(result) == 1
    path = result[0]
    assert path["target_node_id"] == "node-B"
    assert path["path_length"] == 1
    assert path["min_confidence"] == 1.0
    assert path["relationship_types"] == ["PROTECTS"]
    assert path["path_node_ids"] == ["node-A", "node-B"]


def test_bfs_from_two_hops():
    adj = {
        "A": [("B", "PROTECTS", 1.0)],
        "B": [("C", "EXPOSES", 0.8)],
    }
    result = _bfs_from("A", adj)
    assert len(result) == 2
    two_hop = next(r for r in result if r["target_node_id"] == "C")
    assert two_hop["path_length"] == 2
    assert two_hop["min_confidence"] == 0.8
    assert two_hop["relationship_types"] == ["PROTECTS", "EXPOSES"]


def test_bfs_from_does_not_revisit_nodes():
    adj = {
        "A": [("B", "PROTECTS", 1.0), ("C", "EXPOSES", 1.0)],
        "B": [("C", "MEMBER_OF", 1.0)],
    }
    result = _bfs_from("A", adj)
    target_nodes = [r["target_node_id"] for r in result]
    assert target_nodes.count("C") == 1


def test_compute_attack_paths_returns_zero_when_no_finding_nodes():
    with patch("scanner.graph.path_traversal.psycopg2.connect") as mock_connect:
        conn = MagicMock()
        mock_connect.return_value = conn
        cur = MagicMock()
        cur.__enter__ = lambda s: s
        cur.__exit__ = MagicMock(return_value=False)
        conn.cursor.return_value = cur
        # adjacency returns empty; finding_nodes returns empty
        cur.fetchall.return_value = []

        result = compute_attack_paths("scan-1", "tenant-1", "postgresql://x")

    assert result == 0


def test_compute_attack_paths_handles_db_error_gracefully():
    with patch("scanner.graph.path_traversal.psycopg2.connect") as mock_connect:
        mock_connect.side_effect = Exception("DB unavailable")
        result = compute_attack_paths("scan-1", "tenant-1", "postgresql://x")

    assert result == 0
