from types import SimpleNamespace

import scanner.rules.az_cache_001 as az_cache_001
import scanner.rules.az_cosmos_001 as az_cosmos_001
import scanner.rules.az_cosmos_002 as az_cosmos_002
import scanner.rules.az_db_005 as az_db_005
import scanner.rules.az_db_006 as az_db_006
import scanner.rules.az_db_007 as az_db_007


RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/sql"


class Client:
    def __init__(self, server=None, va=None, audit=None, cosmos=None, cache=None):
        self.server = server
        self.va = va
        self.audit = audit
        self.cosmos = cosmos or []
        self.cache = cache or []

    def get_sql_servers(self):
        return [self.server] if self.server else []

    def parse_resource_id(self, value):
        return {"resource_group": "rg", "name": "sql"}

    def get_sql_server_vulnerability_assessment(self, *_):
        return self.va

    def get_sql_server_azure_ad_only_authentication(self, *_):
        return self.server.azure_ad_only_authentication

    def get_sql_server_auditing_policy(self, *_):
        return self.audit

    def get_cosmos_accounts(self):
        return self.cosmos

    def get_managed_caches(self):
        return self.cache


def server(**kwargs):
    values = {"id": RID, "name": "sql", "tags": {}}
    values.update(kwargs)
    return SimpleNamespace(**values)


def account(resource_type, name, **kwargs):
    values = {"id": f"/subscriptions/s/{resource_type}/{name}", "name": name, "tags": {}}
    values.update(kwargs)
    return SimpleNamespace(**values)


def test_sql_identity_and_vulnerability_rules_are_opt_in():
    s = server(
        tags={"oshield:entra-only-required": "true", "oshield:sql-va-required": "true"},
        azure_ad_only_authentication=False,
    )
    c = Client(s, va=SimpleNamespace(is_enabled=False))
    assert az_db_005.scan(c, "s")[0]["rule_id"] == "AZ-DB-005"
    assert az_db_006.scan(c, "s")[0]["rule_id"] == "AZ-DB-006"
    assert az_db_005.scan(Client(server(azure_ad_only_authentication=False)), "s") == []


def test_sql_missing_vulnerability_assessment_is_noncompliant():
    s = server(tags={"oshield:sql-va-required": "true"}, azure_ad_only_authentication=True)
    assert az_db_006.scan(Client(s, va=False), "s")[0]["rule_id"] == "AZ-DB-006"


def test_sql_audit_retention_flags_only_explicitly_short_retention():
    s = server(tags={"oshield:sql-audit-required": "true"})
    c = Client(s, audit=SimpleNamespace(state="Enabled", retention_days=30))
    assert az_db_007.scan(c, "s")[0]["metadata"]["retention_days"] == 30
    assert az_db_007.scan(Client(s, audit=SimpleNamespace(state="Enabled", retention_days=90)), "s") == []
    assert az_db_007.scan(Client(s, audit=SimpleNamespace(state="Enabled", retention_days=0)), "s") == []
    assert az_db_007.scan(Client(s, audit=False), "s")[0]["metadata"]["state"] == "missing"


def test_cosmos_rules_honor_opt_in_tags_and_secure_values():
    local = account(
        "Microsoft.DocumentDB/databaseAccounts",
        "cosmos",
        disable_local_auth=False,
        public_network_access="Enabled",
        tags={"oshield:cosmos-local-auth-disabled": "true", "oshield:cosmos-public-access-disabled": "true"},
    )
    c = Client(cosmos=[local])
    assert az_cosmos_001.scan(c, "s")[0]["rule_id"] == "AZ-COSMOS-001"
    assert az_cosmos_002.scan(c, "s")[0]["rule_id"] == "AZ-COSMOS-002"
    secure = account(
        "Microsoft.DocumentDB/databaseAccounts",
        "secure",
        disable_local_auth=True,
        public_network_access="Disabled",
        tags={"oshield:cosmos-local-auth-disabled": "true", "oshield:cosmos-public-access-disabled": "true"},
    )
    assert az_cosmos_001.scan(Client(cosmos=[secure]), "s") == []
    assert az_cosmos_002.scan(Client(cosmos=[secure]), "s") == []


def test_cache_rule_flags_public_or_weak_tls():
    cache = account(
        "Microsoft.Cache/Redis",
        "cache",
        public_network_access="Enabled",
        minimum_tls_version="1.2",
        tags={"oshield:cache-private-tls-required": "true"},
    )
    assert az_cache_001.scan(Client(cache=[cache]), "s")[0]["rule_id"] == "AZ-CACHE-001"
    secure = account(
        "Microsoft.Cache/Redis",
        "secure",
        public_network_access="Disabled",
        minimum_tls_version="1.2",
        tags={"oshield:cache-private-tls-required": "true"},
    )
    assert az_cache_001.scan(Client(cache=[secure]), "s") == []
