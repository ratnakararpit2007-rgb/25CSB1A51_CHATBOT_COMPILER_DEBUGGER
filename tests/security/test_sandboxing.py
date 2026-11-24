"""Unit tests for Area 4: Sandboxing and Isolation."""

import os
import unittest

from sandbox_runner import SandboxJob, get_sanitized_sandbox_env


class TestSandboxingAndIsolation(unittest.TestCase):
    def test_environment_variable_scrubbing(self):
        """Host secrets and credentials are completely scrubbed from sandbox environment."""
        # Inject mock secrets in os.environ
        os.environ["GEMINI_API_KEY"] = "AIzaSySecretKeyToScrub"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "SecretAwsKeyToScrub"
        os.environ["GITHUB_TOKEN"] = "ghp_PersonalAccessToken"
        os.environ["MY_CUSTOM_API_KEY"] = "CustomSecretKey"

        try:
            scrubbed = get_sanitized_sandbox_env("/tmp/test_workdir")
            self.assertNotIn("GEMINI_API_KEY", scrubbed)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", scrubbed)
            self.assertNotIn("GITHUB_TOKEN", scrubbed)
            self.assertNotIn("MY_CUSTOM_API_KEY", scrubbed)
            self.assertEqual(scrubbed["TMPDIR"], "/tmp/test_workdir")
            self.assertEqual(scrubbed["LC_ALL"], "C.UTF-8")
        finally:
            os.environ.pop("GEMINI_API_KEY", None)
            os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("MY_CUSTOM_API_KEY", None)

    def test_local_sandbox_execution_and_isolation(self):
        """Local sandbox executes standard code and captures stdout/stderr in isolation."""
        code = '#include <iostream>\nint main() { std::cout << "SANDBOX_VERIFIED" << std::endl; return 0; }'
        job = SandboxJob(code, language="cpp", force_mode="local")
        try:
            c_stat, c_out, c_err = job.compile()
            self.assertEqual(c_stat, 0, f"Compilation failed: {c_err}")

            r_stat, r_out, r_err = job.run_binary()
            self.assertEqual(r_stat, 0, f"Run failed: {r_err}")
            self.assertIn("SANDBOX_VERIFIED", r_out)
        finally:
            job.close()

    def test_sandbox_job_teardown_removes_workdir(self):
        """SandboxJob.close() cleans up temporary workspace files."""
        code = 'print("cleanup test")'
        job = SandboxJob(code, language="python", force_mode="local")
        workdir = job.workdir
        self.assertTrue(os.path.exists(workdir))
        job.close()
        self.assertFalse(os.path.exists(workdir))


if __name__ == "__main__":
    unittest.main()
