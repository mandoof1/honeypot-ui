"""Research scanners must be told apart from attackers.

Not filtered out — attributed. A Censys probe is real data about what the
internet does to an exposed host, and discarding it would make the capture
unauditable. But counting it as an attack makes every figure the project
reports incomparable with anything.
"""

import os

from app.models import UserRole
from app.services.scanners import ScannerRegistry, scanner_registry

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

PROBE = {
    "protocol": "ssh",
    "attacker_ip": "162.142.125.13",
    # Measured flow, so the stage-1 model has something to classify.
    "flow": {"duration": 42.0, "fwd_packets": 30, "fwd_bytes": 2200, "bwd_bytes": 9800, "fwd_max": 512, "bwd_max": 1460, "fwd_iat_mean": 1.2, "fwd_iat_max": 8.0, "flow_iat_max": 8.0},
    "started_at": "2026-05-05T05:05:00Z",
    "status": "completed",
    "duration_seconds": 0.4,
    "commands": [],
    "payload": "",
    "uploads": [],
    "failed_logins": 1,
    "packets": [{"type": "handshake", "size": 120}, {"type": "data", "size": 44}],
}


class TestRegistry:
    def test_known_operators_are_identified(self):
        assert scanner_registry.identify("162.142.125.13") == "censys"
        assert scanner_registry.identify("71.6.135.131") == "shodan"
        assert scanner_registry.identify("184.105.247.1") == "shadowserver"

    def test_ordinary_addresses_are_not(self):
        assert scanner_registry.identify("185.220.101.5") is None
        assert scanner_registry.identify("8.8.8.8") is None

    def test_malformed_input_does_not_raise(self):
        assert scanner_registry.identify("not-an-ip") is None
        assert scanner_registry.identify("") is None
        assert scanner_registry.identify(None) is None

    def test_a_zero_length_prefix_cannot_label_the_internet(self):
        """A malformed list entry must not silently mark every session."""
        registry = ScannerRegistry()
        registry._compile({"broken": ["0.0.0.0/0", "0.0.0.0/32", "10.0.0.0/8"]})
        registry._loaded = True
        assert registry.identify("185.220.101.5") is None
        assert registry.identify("10.1.2.3") == "broken"

    def test_the_most_specific_network_wins(self):
        registry = ScannerRegistry()
        registry._compile({"broad": ["10.0.0.0/8"], "narrow": ["10.1.2.0/24"]})
        registry._loaded = True
        assert registry.identify("10.1.2.3") == "narrow"
        assert registry.identify("10.9.9.9") == "broad"

    def test_malformed_cidrs_are_skipped_not_fatal(self):
        registry = ScannerRegistry()
        registry._compile({"mixed": ["not-a-cidr", "10.0.0.0/8"]})
        registry._loaded = True
        assert registry.identify("10.0.0.1") == "mixed"


class TestPipeline:
    async def _ingest(self, client, auth_headers, payload):
        admin = await auth_headers(UserRole.ADMIN)
        node = await client.post(
            "/api/v1/nodes/",
            headers=admin,
            json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9",
                  "port": 2222},
        )
        node_id = node.json()["id"]
        response = await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            headers=INGEST_HEADERS,
            json=payload,
        )
        assert response.status_code == 200, response.text
        return response.json()["session_id"], admin

    async def test_a_scanner_probe_is_labelled(self, client, auth_headers):
        session_id, admin = await self._ingest(client, auth_headers, PROBE)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        assert body["scanner_operator"] == "censys"

    async def test_the_probe_is_still_recorded_in_full(self, client, auth_headers):
        """Attribution, not suppression."""
        session_id, admin = await self._ingest(client, auth_headers, PROBE)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        assert body["attacker_ip"] == "162.142.125.13"
        assert body["attack_category"] is not None

    async def test_an_attacker_is_not_labelled(self, client, auth_headers):
        session_id, admin = await self._ingest(
            client, auth_headers, {**PROBE, "attacker_ip": "185.220.101.5"}
        )
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        assert body["scanner_operator"] is None


class TestDiscardedMeasurements:
    async def _ingest(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node = await client.post(
            "/api/v1/nodes/",
            headers=admin,
            json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9",
                  "port": 2222},
        )
        response = await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node.json()['id']}",
            headers=INGEST_HEADERS,
            json={**PROBE, "attacker_ip": "185.220.101.5"},
        )
        assert response.status_code == 200, response.text
        return response.json()["session_id"], admin

    async def test_the_full_class_distribution_is_kept(self, client, auth_headers):
        """0.34/0.33/0.33 and 0.98/0.01/0.01 were stored identically."""
        session_id, admin = await self._ingest(client, auth_headers)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        probabilities = body["class_probabilities"]
        assert probabilities and len(probabilities) > 1
        assert abs(sum(probabilities.values()) - 1.0) < 0.01
        assert max(probabilities.values()) == body["attack_confidence"]

    async def test_analysis_time_is_persisted_not_only_logged(
        self, client, auth_headers
    ):
        """NFR-2 claims a 200 ms budget; it has to be evidenced, not asserted."""
        session_id, admin = await self._ingest(client, auth_headers)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        assert body["analysis_ms"] is not None
        assert body["analysis_ms"] > 0

    async def test_the_packet_summary_column_is_written(
        self, client, auth_headers, db_session
    ):
        """Indexed since migration 001, never populated."""
        from sqlalchemy import select
        from app.models import HoneypotSession

        session_id, _ = await self._ingest(client, auth_headers)
        row = (
            await db_session.execute(
                select(HoneypotSession).where(HoneypotSession.id == session_id)
            )
        ).scalar_one()

        summary = row.network_packets_summary
        assert summary is not None
        assert summary["count"] == 2
        assert summary["total_bytes"] == 164
        assert summary["by_type"]["handshake"] == {"count": 1, "bytes": 120}


class TestListFiltering:
    async def test_scanners_can_be_excluded_from_the_view(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node = await client.post(
            "/api/v1/nodes/",
            headers=admin,
            json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9",
                  "port": 2222},
        )
        node_id = node.json()["id"]
        for ip in ("162.142.125.13", "185.220.101.5"):
            response = await client.post(
                f"/api/v1/sessions/ingest-internal?node_id={node_id}",
                headers=INGEST_HEADERS,
                json={**PROBE, "attacker_ip": ip},
            )
            assert response.status_code == 200, response.text

        everything = await client.get("/api/v1/sessions/", headers=admin)
        assert everything.json()["total"] == 2

        attackers = await client.get(
            "/api/v1/sessions/?exclude_scanners=true", headers=admin
        )
        body = attackers.json()
        assert body["total"] == 1
        assert body["sessions"][0]["attacker_ip"] == "185.220.101.5"

    async def test_including_them_is_the_default(self, client, auth_headers):
        """Silently hiding traffic would misrepresent what the honeypot saw."""
        admin = await auth_headers(UserRole.ADMIN)
        node = await client.post(
            "/api/v1/nodes/",
            headers=admin,
            json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9",
                  "port": 2222},
        )
        await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node.json()['id']}",
            headers=INGEST_HEADERS,
            json=PROBE,
        )
        assert (await client.get("/api/v1/sessions/", headers=admin)).json()["total"] == 1
