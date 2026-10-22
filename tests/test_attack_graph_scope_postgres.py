"""Graph and path reads must preserve signed subscription boundaries."""

import os
import time

import jwt
import psycopg2
import pytest

from tests.test_graph_paths_postgres import path_scope, risky_scan  # noqa: F401

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="requires PostgreSQL")


def test_same_tenant_foreign_subscription_is_not_readable(path_scope, app, client):  # noqa: F811
    tenant, subscription, dsn, scan = path_scope
    foreign = subscription + "-other"
    own_scan, foreign_scan = scan(), scan(foreign)
    risky_scan(tenant, subscription, dsn, own_scan)
    risky_scan(tenant, foreign, dsn, foreign_scan)
    token = jwt.encode(
        {
            "sub": "reader",
            "role": "viewer",
            "tid": tenant,
            "subscription_id": subscription,
            "exp": int(time.time()) + 60,
        },
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/attack-graph", headers=headers)
    assert response.status_code == 200
    assert {node["subscription_id"] for node in response.json["nodes"]} == {subscription}
    assert client.get(f"/api/v1/attack-graph?subscription_id={foreign}", headers=headers).status_code == 400
    paths = client.get(f"/api/v1/attack-paths?scan_id={foreign_scan}", headers=headers)
    assert paths.status_code == 200 and paths.json["paths"] == []
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT path_id::text FROM attack_paths WHERE scan_id=%s", (foreign_scan,))
        foreign_path = cur.fetchone()[0]
    assert client.get(f"/api/v1/attack-paths/{foreign_path}", headers=headers).status_code == 404
    own_paths = client.get(f"/api/v1/attack-paths?scan_id={own_scan}", headers=headers)
    assert own_paths.status_code == 200 and len(own_paths.json["paths"]) == 1
    own_path_id = own_paths.json["paths"][0]["path_id"]
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT node_id FROM graph_nodes WHERE tenant_id=%s AND subscription_id=%s LIMIT 1", (tenant, foreign)
        )
        foreign_node = str(cur.fetchone()[0])
        cur.execute(
            "UPDATE attack_paths SET path_node_ids=path_node_ids || %s::uuid WHERE path_id=%s",
            (foreign_node, own_path_id),
        )
    assert client.get(f"/api/v1/attack-paths?scan_id={own_scan}", headers=headers).json["paths"] == []
    assert client.get(f"/api/v1/attack-paths/{own_path_id}", headers=headers).status_code == 404
