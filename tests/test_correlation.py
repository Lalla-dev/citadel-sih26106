"""
Citadel Phase 5 Tests - Threat Correlation & Interactive Threat Graph
Tests node-edge graph construction, entity relationships, critical pivots, and API endpoints.
"""
import unittest
from backend.correlation import build_threat_graph, NODE_COLORS
from backend.parser import parse_eml
from backend.detector import CitadelDetectorOrchestrator
from fastapi.testclient import TestClient
from backend.main import app


class TestCorrelationGraph(unittest.TestCase):
    """Test standalone Threat Correlation Graph Engine."""

    def setUp(self):
        self.orchestrator = CitadelDetectorOrchestrator()

    def test_graph_structure_for_phishing_email(self):
        """Graph should create email, sender, domain, URL, and threat actor nodes."""
        raw_eml = (
            "From: security-alert@microsoft-support-verify.com\r\n"
            "To: employee@corp.com\r\n"
            "Subject: Security Notice - Immediate Verification Required\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            "Verify your account at https://secure-portal.xyz/login immediately.\r\n"
        ).encode()

        parsed = parse_eml(raw_eml)
        analysis = self.orchestrator.analyze(parsed, "phish_test.eml")

        self.assertIsNotNone(analysis.threat_graph)
        graph = analysis.threat_graph
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertIn("summary", graph)

        node_types = set(n["type"] for n in graph["nodes"])
        self.assertIn("EMAIL", node_types)
        self.assertIn("SENDER", node_types)
        self.assertIn("DOMAIN", node_types)
        self.assertIn("URL", node_types)

        # Edges should connect nodes
        self.assertGreater(len(graph["edges"]), 0)
        relationships = set(e["relationship"] for e in graph["edges"])
        self.assertIn("ORIGINATED_FROM", relationships)
        self.assertIn("CONTAINS_HYPERLINK", relationships)

    def test_threat_actor_attribution_node(self):
        """When IOC matches known threat group, THREAT_ACTOR node should be created."""
        raw_eml = (
            "From: test@corp.com\r\n"
            "To: target@corp.com\r\n"
            "Subject: Urgent Link\r\n\r\n"
            "Please check https://secure-portal.xyz/payload\r\n"
        ).encode()
        parsed = parse_eml(raw_eml)
        analysis = self.orchestrator.analyze(parsed, "ioc.eml")

        graph = analysis.threat_graph
        actor_nodes = [n for n in graph["nodes"] if n["type"] == "THREAT_ACTOR"]
        self.assertGreater(len(actor_nodes), 0)
        self.assertIn("TA505", actor_nodes[0]["label"])

    def test_benign_email_graph(self):
        """Benign email should generate clean graph with minimal nodes."""
        raw_eml = (
            "From: alice@google.com\r\n"
            "To: bob@google.com\r\n"
            "Subject: Sync\r\n\r\n"
            "Meeting at 2 PM.\r\n"
        ).encode()
        parsed = parse_eml(raw_eml)
        analysis = self.orchestrator.analyze(parsed, "benign.eml")

        graph = analysis.threat_graph
        self.assertGreaterEqual(len(graph["nodes"]), 2)
        # Should have zero critical pivots
        self.assertEqual(len(graph["summary"]["critical_pivots"]), 0)


class TestCorrelationAPI(unittest.TestCase):
    """Test correlation graph API endpoints."""

    def setUp(self):
        self.client = TestClient(app)

    def test_sample_graph_endpoint(self):
        """API should return graph structure with nodes and edges."""
        response = self.client.get("/api/sample/credential_phishing_link.eml/graph")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("summary", data)
        self.assertGreater(len(data["nodes"]), 1)


if __name__ == "__main__":
    unittest.main()
