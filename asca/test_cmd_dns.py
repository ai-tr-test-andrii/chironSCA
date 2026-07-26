"""
Tests for the /cmd/dns endpoint — verifying that the command injection
vulnerability (CWE-77) in cmd_dns() is properly fixed.

The fix replaces:
    subprocess.check_output("nslookup " + domain, shell=True)
with:
    subprocess.check_output(["nslookup", domain], shell=False)

This ensures the domain value is passed as a separate argv element and is
never interpreted by a shell, eliminating the command injection vector.
"""

import subprocess
import pytest
from unittest.mock import patch, MagicMock

# Import the Flask app and its initialisation helper.
from asca.sql_injection_large import app, init_db


@pytest.fixture(autouse=True)
def setup_db():
    """Initialise the in-memory SQLite database before every test."""
    init_db()


@pytest.fixture()
def client():
    """Return a Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Helper: capture the arguments that subprocess.check_output is called with.
# ---------------------------------------------------------------------------

def _mock_check_output(args, **kwargs):
    """Fake nslookup output used in happy-path tests."""
    return b"Server:  8.8.8.8\nName:    example.com\nAddress: 93.184.216.34\n"


# ---------------------------------------------------------------------------
# 1. Verify the fix: shell=False and argv list
# ---------------------------------------------------------------------------

class TestCmdDnsFixStructure:
    """Verify that the subprocess call uses shell=False and an argv list."""

    def test_check_output_called_with_list_not_string(self, client):
        """subprocess.check_output must receive a list, not a string."""
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"nslookup output"
            client.get("/cmd/dns?domain=example.com")

            assert mock_co.called, "subprocess.check_output was not called"
            call_args, call_kwargs = mock_co.call_args
            # First positional argument must be a list (argv), not a str.
            cmd = call_args[0]
            assert isinstance(cmd, list), (
                f"Expected argv list, got {type(cmd).__name__}: {cmd!r}. "
                "Passing a string with shell=True enables command injection."
            )

    def test_check_output_called_with_shell_false(self, client):
        """subprocess.check_output must be called with shell=False."""
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"nslookup output"
            client.get("/cmd/dns?domain=example.com")

            _, call_kwargs = mock_co.call_args
            shell_value = call_kwargs.get("shell", False)
            assert shell_value is False, (
                f"shell={shell_value!r} — must be False to prevent command injection."
            )

    def test_domain_is_separate_argv_element(self, client):
        """The domain must be the second element of the argv list, not concatenated."""
        domain = "example.com"
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"nslookup output"
            client.get(f"/cmd/dns?domain={domain}")

            call_args, _ = mock_co.call_args
            cmd = call_args[0]
            assert len(cmd) >= 2, "argv list must have at least two elements"
            assert cmd[0] == "nslookup", f"First argv element must be 'nslookup', got {cmd[0]!r}"
            assert cmd[1] == domain, (
                f"Second argv element must be the domain '{domain}', got {cmd[1]!r}. "
                "The domain must NOT be concatenated into the command string."
            )


# ---------------------------------------------------------------------------
# 2. Security: command-injection payloads must NOT be executed as shell commands
# ---------------------------------------------------------------------------

class TestCmdDnsCommandInjectionBlocked:
    """
    Confirm that shell meta-characters in the domain are passed verbatim
    to nslookup (as data) instead of being interpreted by a shell.

    With shell=False the shell is never invoked, so any injected command
    sequence remains inert — it is just a string argument to nslookup.
    """

    INJECTION_PAYLOADS = [
        "example.com; id",
        "example.com && whoami",
        "example.com | cat /etc/passwd",
        "example.com`id`",
        "example.com$(id)",
        "; rm -rf /",
        "example.com\nid",
    ]

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_injection_payload_passed_as_single_argument(self, client, payload):
        """
        The injection payload must be passed as a single argv string to nslookup,
        not split and interpreted by a shell.
        """
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"nslookup output"
            client.get(f"/cmd/dns?domain={payload}")

            call_args, call_kwargs = mock_co.call_args
            cmd = call_args[0]
            shell_value = call_kwargs.get("shell", False)

            # The fix must use shell=False.
            assert shell_value is False, (
                "shell=True detected — injection payload would be interpreted by the shell."
            )

            # The entire payload must be a single element (not split by the shell).
            assert isinstance(cmd, list), "Command must be passed as an argv list."
            assert len(cmd) == 2, (
                f"Expected exactly ['nslookup', payload], got {cmd!r}. "
                "If shell=True were used, the shell would split and execute the payload."
            )
            assert cmd[1] == payload, (
                f"Domain payload must be passed verbatim as argv[1], got {cmd[1]!r}."
            )

    def test_no_extra_subprocess_calls_for_injection_attempt(self, client):
        """
        With shell=False only a single subprocess call should be made.
        A successful injection would spawn additional processes.
        """
        payload = "example.com; id"
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"nslookup output"
            client.get(f"/cmd/dns?domain={payload}")

            assert mock_co.call_count == 1, (
                f"Expected exactly 1 subprocess call, got {mock_co.call_count}. "
                "Multiple calls may indicate injected commands were executed."
            )


# ---------------------------------------------------------------------------
# 3. Functional / happy-path tests
# ---------------------------------------------------------------------------

class TestCmdDnsFunctional:
    """Verify normal operation after the security fix."""

    def test_valid_domain_returns_200(self, client):
        """A well-formed domain lookup must return HTTP 200."""
        with patch("subprocess.check_output", side_effect=_mock_check_output):
            response = client.get("/cmd/dns?domain=example.com")
        assert response.status_code == 200

    def test_response_contains_nslookup_output(self, client):
        """The response body must contain the output from nslookup."""
        with patch("subprocess.check_output", side_effect=_mock_check_output):
            response = client.get("/cmd/dns?domain=example.com")
        assert b"example.com" in response.data

    def test_missing_domain_parameter(self, client):
        """When 'domain' is omitted, check_output receives an empty string as argv[1]."""
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b""
            response = client.get("/cmd/dns")

        assert mock_co.called
        call_args, _ = mock_co.call_args
        cmd = call_args[0]
        # An empty domain becomes argv[1] == "" — still safe (no shell interpretation).
        assert cmd == ["nslookup", ""], f"Expected ['nslookup', ''], got {cmd!r}"

    def test_mimetype_is_plain_text(self, client):
        """The response Content-Type must be text/plain."""
        with patch("subprocess.check_output", side_effect=_mock_check_output):
            response = client.get("/cmd/dns?domain=example.com")
        assert "text/plain" in response.content_type

    def test_ipv4_address_as_domain(self, client):
        """An IPv4 address literal must be forwarded as-is to nslookup."""
        ip = "8.8.8.8"
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"name = dns.google."
            client.get(f"/cmd/dns?domain={ip}")

        call_args, _ = mock_co.call_args
        cmd = call_args[0]
        assert cmd == ["nslookup", ip]

    def test_subdomain_as_domain(self, client):
        """A multi-level subdomain must be forwarded verbatim."""
        subdomain = "mail.internal.corp.example.com"
        with patch("subprocess.check_output") as mock_co:
            mock_co.return_value = b"Name: mail.internal.corp.example.com"
            client.get(f"/cmd/dns?domain={subdomain}")

        call_args, _ = mock_co.call_args
        cmd = call_args[0]
        assert cmd == ["nslookup", subdomain]
