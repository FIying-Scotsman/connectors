import gzip
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from csis_client import CSISAuthError, CSISClient
from csis_client.api_client import TOKEN_URL


def _token_response(**payload) -> MagicMock:
    return MagicMock(
        ok=True,
        json=MagicMock(return_value={"access_token": "test-token", **payload}),
    )


def _feed_response(payload: bytes) -> MagicMock:
    return MagicMock(
        content=gzip.compress(payload), is_redirect=False, is_permanent_redirect=False
    )


@pytest.fixture
def client() -> CSISClient:
    client = CSISClient(client_id="id", client_secret="secret")
    client.session = MagicMock()
    client.session.post.return_value = _token_response(expires_in=299)
    client.session.get.return_value = _feed_response(b"")
    return client


def test_fetch_feed_parses_ndjson(client) -> None:
    rows = [{"kind": "domain", "value": "evil.example.com"}, {"kind": "ip"}]
    payload = "\n".join(json.dumps(r) for r in rows) + "\n\n  \n"
    client.session.get.return_value = _feed_response(payload.encode())

    assert client.fetch_feed("essential") == rows
    assert client.session.post.call_args.args[0] == TOKEN_URL
    headers = client.session.get.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer test-token"


def test_fetch_feed_follows_redirect_without_auth_header(client) -> None:
    redirect = MagicMock(is_redirect=True, headers={"Location": "https://gcs/signed"})
    client.session.get.side_effect = [redirect, _feed_response(b'{"kind": "ip"}')]

    assert client.fetch_feed("essential") == [{"kind": "ip"}]
    first, second = client.session.get.call_args_list
    assert first.kwargs["allow_redirects"] is False
    assert second.args[0] == "https://gcs/signed"
    assert "headers" not in second.kwargs


def test_fetch_feed_raises_eagerly(client) -> None:
    client.session.get.return_value.raise_for_status.side_effect = RuntimeError("500")

    with pytest.raises(RuntimeError):
        client.fetch_feed("essential")


def test_token_is_cached_until_expiry(client) -> None:
    client.fetch_feed("essential")
    client.fetch_feed("advanced")
    assert client.session.post.call_count == 1

    client._token_expires_at = datetime(2000, 1, 1, tzinfo=timezone.utc)
    client.fetch_feed("essential")
    assert client.session.post.call_count == 2


def test_token_missing_access_token_raises(client) -> None:
    client.session.post.return_value = MagicMock(
        ok=True, json=MagicMock(return_value={})
    )

    with pytest.raises(CSISAuthError):
        client.fetch_feed("essential")


def test_token_error_surfaces_response_body(client) -> None:
    client.session.post.return_value = MagicMock(
        ok=False, status_code=401, text='{"error": "invalid_client"}'
    )

    with pytest.raises(CSISAuthError, match="invalid_client"):
        client.fetch_feed("essential")
