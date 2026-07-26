"""
Tests for the /cmd/dns endpoint command-injection fix.

The vulnerability (CWE-77) was: `subprocess.check_output("nslookup " + domain, shell=True)`
which allowed an attacker to inject arbitrary shell commands via the `domain` query parameter.

The fix passes an argv list to `subprocess.check_output` with `shell=False`, so the shell
never processes the domain value and metacharacters are treated as literal arguments.
"""
import subprocess
import unittest
from unittest.mock import patch, MagicMock

import sys
import os

# Ensure the asca package is importable when running from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asca.sql_injection_large import app, init_db


class TestCmdDnsCommandInjectionFix(unittest.TestCase):
    """Verify that /cmd/dns is no longer vulnerable to command injection."""

    def setUp(self):
        app.config["TESTING"] = True
        init_db()
        self.client = app.test_client()

    # ------------------------------------------------------------------
    # Helper: intercept the actual subprocess call so tests are hermetic.
    # ------------------------------------------------------------------

    def _make_check_output_mock(self, return_value=b"Server: 8.8.8.8\nName: example.com"):
        """Return a mock that records the call args and returns safe output."""
        mock = MagicMock(return_value=return_value)
        return mock

    # ------------------------------------------------------------------
    # Positive cases: normal domain names work.
    # ------------------------------------------------------------------

    def test_valid_domain_calls_nslookup_argv(self):
        """A benign domain causes check_output to be called with an argv list."""
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            resp = self.client.get("/cmd/dns?domain=example.com")
            self.assertEqual(resp.status_code, 200)
            # subprocess.check_output must have been called exactly once.
            mock_co.assert_called_once()
            call_args, call_kwargs = mock_co.call_args
            # First positional argument must be a list, not a string.
            cmd = call_args[0]
            self.assertIsInstance(cmd, list,
                "check_output must be called with a list (argv), not a shell string")
            self.assertEqual(cmd[0], "nslookup")
            self.assertEqual(cmd[1], "example.com")

    def test_valid_domain_shell_is_false(self):
        """shell=False must be explicitly set (or omitted, which defaults to False)."""
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            self.client.get("/cmd/dns?domain=example.com")
            _, call_kwargs = mock_co.call_args
            # shell must not be True; False or absent are both safe.
            shell_value = call_kwargs.get("shell", False)
            self.assertFalse(shell_value,
                "shell=True would allow command injection; it must be False")

    def test_response_body_contains_nslookup_output(self):
        """The endpoint returns the raw bytes from nslookup."""
        fake_output = b"Non-authoritative answer:\nName: example.com"
        with patch("subprocess.check_output", return_value=fake_output):
            resp = self.client.get("/cmd/dns?domain=example.com")
            self.assertIn(b"example.com", resp.data)

    # ------------------------------------------------------------------
    # Security / negative cases: injection payloads must NOT be executed.
    # ------------------------------------------------------------------

    def test_semicolon_injection_payload_passed_as_literal_argument(self):
        """
        Payload `; cat /etc/passwd` must be passed as a single literal argument
        to nslookup, not interpreted by a shell.  With argv + shell=False the
        shell metacharacter `;` is inert.
        """
        payload = "example.com; cat /etc/passwd"
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            resp = self.client.get(f"/cmd/dns?domain={payload}")
            self.assertEqual(resp.status_code, 200)
            call_args, call_kwargs = mock_co.call_args
            cmd = call_args[0]
            self.assertIsInstance(cmd, list)
            # The entire payload is the second argv element — not split by the shell.
            self.assertEqual(cmd[1], payload)
            # shell=False (or absent) confirmed.
            self.assertFalse(call_kwargs.get("shell", False))

    def test_pipe_injection_payload_passed_as_literal_argument(self):
        """Payload `| id` must not cause a second command to execute."""
        payload = "example.com | id"
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            self.client.get(f"/cmd/dns?domain={payload}")
            call_args, _ = mock_co.call_args
            cmd = call_args[0]
            self.assertIsInstance(cmd, list)
            self.assertEqual(cmd[1], payload)

    def test_ampersand_injection_payload_passed_as_literal_argument(self):
        """Payload `& whoami` must not cause a background command execution."""
        payload = "example.com & whoami"
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            self.client.get(f"/cmd/dns?domain={payload}")
            call_args, _ = mock_co.call_args
            cmd = call_args[0]
            self.assertIsInstance(cmd, list)
            self.assertEqual(cmd[1], payload)

    def test_backtick_injection_payload_passed_as_literal_argument(self):
        """Payload containing backtick command substitution must not execute."""
        payload = "example.com`id`"
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            self.client.get(f"/cmd/dns?domain={payload}")
            call_args, _ = mock_co.call_args
            cmd = call_args[0]
            self.assertIsInstance(cmd, list)
            self.assertEqual(cmd[1], payload)

    def test_dollar_subshell_payload_passed_as_literal_argument(self):
        """Payload using `$(...)` substitution must be treated as a literal string."""
        payload = "example.com$(whoami)"
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            self.client.get(f"/cmd/dns?domain={payload}")
            call_args, _ = mock_co.call_args
            cmd = call_args[0]
            self.assertIsInstance(cmd, list)
            self.assertEqual(cmd[1], payload)

    def test_newline_injection_payload_passed_as_literal_argument(self):
        """Newline-separated payload must not cause a second command to run."""
        payload = "example.com\nwhoami"
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            self.client.get(f"/cmd/dns?domain={payload}")
            call_args, _ = mock_co.call_args
            cmd = call_args[0]
            self.assertIsInstance(cmd, list)
            # The newline-containing string is passed as one argument.
            self.assertEqual(cmd[1], payload)

    def test_empty_domain_uses_argv_form(self):
        """Even an empty domain must go through the safe argv path."""
        with patch("subprocess.check_output", self._make_check_output_mock()) as mock_co:
            self.client.get("/cmd/dns?domain=")
            call_args, call_kwargs = mock_co.call_args
            cmd = call_args[0]
            self.assertIsInstance(cmd, list)
            self.assertFalse(call_kwargs.get("shell", False))

    def test_old_vulnerable_pattern_not_used(self):
        """
        Regression guard: ensure the implementation no longer passes a bare string
        (concatenated command) to subprocess.check_output.

        This is validated by inspecting the source code text of the module.
        """
        import inspect
        import asca.sql_injection_large as module

        source = inspect.getsource(module.cmd_dns)
        # The old pattern was: check_output("nslookup " + domain, shell=True)
        # Confirm the shell=True flag is gone from cmd_dns.
        self.assertNotIn(
            "shell=True", source,
            "cmd_dns must not use shell=True (command injection risk)"
        )
        # Confirm the string-concatenation form is gone.
        self.assertNotIn(
            '"nslookup " + domain', source,
            "cmd_dns must not concatenate the domain into a shell string"
        )
        self.assertNotIn(
            "'nslookup ' + domain", source,
            "cmd_dns must not concatenate the domain into a shell string"
        )


if __name__ == "__main__":
    unittest.main()
