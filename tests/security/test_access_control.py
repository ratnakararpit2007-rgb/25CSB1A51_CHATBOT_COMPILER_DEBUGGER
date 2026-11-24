"""Unit tests for Area 2: Least Privilege Access Control & RBAC."""

import os
import tempfile
import unittest

from access_control import RBACManager, validate_safe_path
from policy_gateway import validate_tool_call


class TestLeastPrivilegeAccessControl(unittest.TestCase):
    def setUp(self):
        self.temp_root = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.temp_root):
            try:
                import shutil
                shutil.rmtree(self.temp_root)
            except OSError:
                pass

    def test_path_traversal_blocked(self):
        """Path traversal with '..' or root escapes is strictly blocked."""
        # Relative traversal
        bad_path = os.path.join(self.temp_root, "../etc/passwd")
        ok, msg = validate_safe_path(bad_path, self.temp_root)
        self.assertFalse(ok)
        self.assertIn("forbidden pattern", msg)

        # Direct escape
        ok2, msg2 = validate_safe_path("/etc/shadow", self.temp_root)
        self.assertFalse(ok2)

    def test_symlink_escape_blocked(self):
        """Symlinks pointing outside sandbox root are resolved and blocked."""
        outside_file = tempfile.NamedTemporaryFile(delete=False)
        outside_file.write(b"secret")
        outside_file.close()

        link_path = os.path.join(self.temp_root, "evil_link")
        try:
            os.symlink(outside_file.name, link_path)
            ok, msg = validate_safe_path(link_path, self.temp_root)
            self.assertFalse(ok)
            self.assertIn("escapes sandbox root", msg)
        finally:
            if os.path.exists(outside_file.name):
                os.remove(outside_file.name)

    def test_legitimate_path_within_sandbox_allowed(self):
        """Legitimate file inside allowed root succeeds."""
        safe_file = os.path.join(self.temp_root, "solution.cpp")
        with open(safe_file, "w") as f:
            f.write("// code")

        ok, msg = validate_safe_path(safe_file, self.temp_root)
        self.assertTrue(ok)
        self.assertEqual(msg, "ok")

    def test_rbac_restricts_actions_by_role(self):
        """RBAC enforces least privilege by role."""
        rbac = RBACManager()

        # Student cannot call export_audit
        ok_student, reason = rbac.is_action_allowed("export_audit", role="student")
        self.assertFalse(ok_student)
        self.assertIn("not permitted for role 'student'", reason)

        # Admin can call export_audit
        ok_admin, _ = rbac.is_action_allowed("export_audit", role="admin")
        self.assertTrue(ok_admin)

        # Student can call standard tools
        ok_compile, _ = rbac.is_action_allowed("compile", role="student")
        self.assertTrue(ok_compile)

        # Unknown role blocked (fail-closed)
        ok_unknown, _ = rbac.is_action_allowed("compile", role="guest_hacker")
        self.assertFalse(ok_unknown)

    def test_policy_gateway_enforces_rbac_and_traversal(self):
        """Policy gateway denies unauthorized roles or traversal args."""
        call = {"thought": "t", "tool": "compile", "args": {}}
        ok, reason, _ = validate_tool_call(call, role="readonly_viewer")
        self.assertFalse(ok)
        self.assertIn("not permitted for role 'readonly_viewer'", reason)

        traversal_call = {"thought": "t", "tool": "run", "args": {"stdin": "../../etc/passwd"}}
        ok2, reason2, _ = validate_tool_call(traversal_call, role="student")
        self.assertFalse(ok2)
        self.assertIn("prohibited path traversal", reason2)


if __name__ == "__main__":
    unittest.main()
