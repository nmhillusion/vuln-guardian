# tests/test_github_client.py
import pytest
from unittest.mock import patch, MagicMock
from src.github_client import GitHubClient


def test_client_sets_auth_header():
    client = GitHubClient("ghp_test_token")
    assert client.client.headers["Authorization"] == "Bearer ghp_test_token"
    assert client.client.headers["Accept"] == "application/vnd.github+json"


def test_client_get_calls_correct_url():
    client = GitHubClient("ghp_test_token")
    with patch.object(client.client, "get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"login": "test"}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        result = client.get("/user")
        mock_get.assert_called_once_with("https://api.github.com/user")
        assert result == {"login": "test"}


def test_client_get_paginated_returns_all_items():
    client = GitHubClient("ghp_test_token")
    with patch.object(client.client, "get") as mock_get:
        mock_response_1 = MagicMock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = [{"id": 1}, {"id": 2}]
        mock_response_1.raise_for_status = MagicMock()
        mock_response_1.links = {"next": {"url": "https://api.github.com/test?page=2"}}

        mock_response_2 = MagicMock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = [{"id": 3}]
        mock_response_2.raise_for_status = MagicMock()
        mock_response_2.links = {}

        mock_get.side_effect = [mock_response_1, mock_response_2]
        result = client.get_paginated("/repos/test-org/test-repo/issues")
        assert len(result) == 3
        assert result[0] == {"id": 1}
