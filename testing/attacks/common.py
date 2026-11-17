
import os
from html.parser import HTMLParser

import requests

BASE_URL = os.getenv(
    "TARGET_BASE_URL",
    "http://127.0.0.1:8081"
).rstrip("/")

USERNAME = "admin"
PASSWORD = "password"
TIMEOUT = 10


class HiddenInputParser(HTMLParser):
    """Extract hidden input fields from an HTML form."""

    def __init__(self):
        super().__init__()
        self.hidden_fields = {}

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return

        fields = dict(attrs)

        if fields.get("type", "").lower() == "hidden":
            name = fields.get("name")
            if name:
                self.hidden_fields[name] = fields.get("value", "")


def create_session():
    """Authenticate with DVWA and verify the session."""

    session = requests.Session()

    login_url = f"{BASE_URL}/login.php"

    # First request: obtain session cookies and login form.
    response = session.get(
        login_url,
        timeout=TIMEOUT
    )
    response.raise_for_status()

    parser = HiddenInputParser()
    parser.feed(response.text)

    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login",
        **parser.hidden_fields
    }

    # Second request: submit credentials and hidden form fields.
    response = session.post(
        login_url,
        data=login_data,
        timeout=TIMEOUT
    )
    response.raise_for_status()

    # Verify access to an authenticated page.
    verification = session.get(
        f"{BASE_URL}/index.php",
        timeout=TIMEOUT,
        allow_redirects=True
    )

    verification.raise_for_status()

    if "/login.php" in verification.url:
        raise RuntimeError(
            "DVWA authentication failed. "
            "The session was redirected to login.php."
        )

    if "Login failed" in verification.text:
        raise RuntimeError("DVWA rejected the credentials.")

    print(f"[+] DVWA authentication verified: {BASE_URL}")

    return session


def send_request(session, endpoint, method="GET", params=None):
    """Send an HTTP request to the configured target."""

    url = f"{BASE_URL}{endpoint}"

    response = session.request(
        method=method,
        url=url,
        params=params,
        timeout=TIMEOUT,
        allow_redirects=True
    )

    return response


def display_result(label, response):
    """Display HTTP response information."""

    print(f"\n--- {label} ---")
    print(f"Status Code : {response.status_code}")
    print(f"Final URL   : {response.url}")
    print(
        f"Content Type: "
        f"{response.headers.get('Content-Type', 'Unknown')}"
    )
    print(f"Response    : {response.text[:250]!r}")
    print("-" * 45)
