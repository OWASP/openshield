"""Detector failure must preserve the last published graph evidence."""

import uuid
from dataclasses import replace

from tests.test_graph_freshness_postgres import counts, snapshot
from tests.test_graph_freshness_postgres import graph_scope as _graph_scope
from tests.test_graph_freshness_postgres import pytestmark as pytestmark

from scanner.graph.graph_populator import populate_graph

graph_scope = _graph_scope


def test_malformed_detector_input_preserves_published_graph(graph_scope):
    tenant, subscription, dsn = graph_scope
    good = replace(snapshot(tenant, subscription), collected_at="2026-10-07T01:00:00Z")
    populate_graph(str(uuid.uuid4()), good, dsn)
    assert counts(dsn, tenant, subscription, current=True) == (2, 1)

    malformed = replace(snapshot(tenant, subscription), collected_at="2026-10-07T02:00:00Z")
    malformed = replace(
        malformed,
        resources=(
            malformed.resources[0],
            replace(malformed.resources[1], properties={"ipConfigurations": [None]}),
        ),
    )
    populate_graph(str(uuid.uuid4()), malformed, dsn)

    assert counts(dsn, tenant, subscription, current=True) == (2, 1)
    assert counts(dsn, tenant, subscription) == (2, 1)
