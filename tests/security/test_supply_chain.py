"""Tests for Area 9: Supply Chain Security & Tool/MCP Allowlisting."""

from __future__ import annotations

import unittest
from supply_chain import load_inventory, verify_lockfile_integrity, verify_plugin_or_mcp


class TestSupplyChainSecurity(unittest.TestCase):
    def test_blocks_unverified_third_party_plugin(self):
        """Proves that un-allowlisted plugins/MCP servers are blocked."""
        ok, reason = verify_plugin_or_mcp("untrusted.malicious_plugin", auth_token="valid_token_12345")
        self.assertFalse(ok)
        self.assertIn("not in the verified allowlist", reason)

    def test_blocks_unauthenticated_mcp_connection(self):
        """Proves that allowlisted plugins without valid credentials fail authentication."""
        # builtin.multi_language_compiler is allowlisted, but lacks token
        ok, reason = verify_plugin_or_mcp("builtin.multi_language_compiler", auth_token="")
        self.assertFalse(ok)
        self.assertIn("requires valid authentication token", reason)

    def test_allows_verified_and_authenticated_mcp_plugin(self):
        """Proves that allowlisted plugins with valid token are authorized."""
        ok, reason = verify_plugin_or_mcp("builtin.multi_language_compiler", auth_token="secure_token_abcdef123")
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")

    def test_lockfile_integrity_pinned_dependencies(self):
        """Proves that requirements.lock exists and dependencies are strictly pinned."""
        ok, msg, pinned = verify_lockfile_integrity()
        self.assertTrue(ok, msg)
        self.assertGreater(len(pinned), 10)
        self.assertIn("requests", pinned)
        self.assertIn("streamlit", pinned)

    def test_inventory_documentation_complete(self):
        """Proves that inventory.json documents runtime, compilers, and sandboxing."""
        inv = load_inventory()
        self.assertIn("components", inv)
        comp_names = [c["name"] for c in inv["components"]]
        self.assertIn("clang_cpp_compiler", comp_names)
        self.assertIn("python_runtime", comp_names)
        self.assertIn("docker_sandbox", comp_names)


if __name__ == "__main__":
    unittest.main()
