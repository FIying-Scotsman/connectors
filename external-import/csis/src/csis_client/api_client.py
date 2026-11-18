"""HTTP client for the CSIS Cyber Data Feed (CDF) API."""

import gzip
import json
from datetime import datetime, timedelta, timezone

import requests

TOKEN_URL = "https://login.csis.com/oauth2/v2/token"
API_BASE_URL = "https://api.csis.com"
FEED_SCOPE = "https://api.csis.com/feed:read"

# Refresh slightly early so a token can't expire mid-download.
TOKEN_REFRESH_MARGIN_SECONDS = 15
DEFAULT_TOKEN_TTL_SECONDS = 299


class CSISAuthError(Exception):
    """CSIS OAuth2 token request failed."""


class CSISClient:
    """OAuth2 client-credentials auth and feed download for CSIS CDF."""

    def __init__(
        self, client_id: str, client_secret: str, request_timeout_seconds: int = 60
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.request_timeout_seconds = request_timeout_seconds
        self.session = requests.Session()
        self._token: str | None = None
        self._token_expires_at: datetime | None = None

    def _get_token(self) -> str:
        now = datetime.now(timezone.utc)
        if self._token and self._token_expires_at and now < self._token_expires_at:
            return self._token

        response = self.session.post(
            TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": FEED_SCOPE,
            },
            timeout=self.request_timeout_seconds,
        )
        if not response.ok:
            # OAuth2 error reason (e.g. 'invalid_client') is only in the body.
            raise CSISAuthError(
                f"CSIS token request failed with HTTP {response.status_code}: "
                f"{response.text.strip()[:500]}"
            )
        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise CSISAuthError("CSIS token response has no 'access_token'.")

        expires_in = int(payload.get("expires_in", DEFAULT_TOKEN_TTL_SECONDS))
        margin = min(TOKEN_REFRESH_MARGIN_SECONDS, expires_in)
        self._token = token
        self._token_expires_at = now + timedelta(seconds=expires_in - margin)
        return token

    def fetch_feed(self, feed_type: str) -> list[dict]:
        """Download a feed and return its NDJSON rows."""
        response = self.session.get(
            f"{API_BASE_URL}/feeds/1.0/feed/{feed_type}",
            headers={
                "Authorization": f"Bearer {self._get_token()}",
                "Accept": "application/json",
            },
            timeout=self.request_timeout_seconds,
            allow_redirects=False,
        )
        if response.is_redirect or response.is_permanent_redirect:
            # Signed GCS URL: rejects requests carrying the CSIS Authorization header.
            response = self.session.get(
                response.headers["Location"], timeout=self.request_timeout_seconds
            )
        response.raise_for_status()

        text = gzip.decompress(response.content).decode("utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]
