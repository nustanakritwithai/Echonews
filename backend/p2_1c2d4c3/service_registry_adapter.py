"""P2.1c.2d.4c.3 least-privilege durable registry service adapter.

This class changes only the sealed database lookup surface. Signature validation,
session-key derivation, snapshot validation and ActorBinding construction remain the
proven P2.1c.2c.3 implementation. The SQL is fixed in code and never comes from a
request or environment variable.
"""
from postgres_registry_adapter import PostgresRegistryAdapter


class ServicePostgresRegistryAdapter(PostgresRegistryAdapter):
    """Resolve verified identities through the dedicated registry runtime wrapper."""

    _LOOKUP_SQL = """SELECT echo_identity.runtime_lookup_session(%s,%s,%s),
                              floor(extract(epoch FROM clock_timestamp())*1000)::bigint"""
