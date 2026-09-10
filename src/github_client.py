# src/github_client.py
from __future__ import annotations

import httpx
import time
import logging

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"

MAX_RETRIES = 3
RETRY_BACKOFF = 2


class GitHubClient:
    def __init__(self, token: str) -> None:
        self.client = httpx.Client(
            base_url=GITHUB_API_BASE,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    def get(self, path: str) -> dict:
        return self._request("GET", path)

    def get_paginated(self, path: str, per_page: int = 100) -> list[dict]:
        items: list[dict] = []
        url: str | None = f"{GITHUB_API_BASE}{path}"
        if "?" in url:
            url += f"&per_page={per_page}"
        else:
            url += f"?per_page={per_page}"

        while url:
            response = self.client.get(url)
            response.raise_for_status()
            items.extend(response.json())
            url = response.links.get("next", {}).get("url")
        return items

    def post(self, path: str, json: dict) -> dict:
        return self._request("POST", path, json=json)

    def _request(self, method: str, path: str, **kwargs) -> dict:
        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                if method == "GET":
                    response = self.client.get(f"{GITHUB_API_BASE}{path}", **kwargs)
                elif method == "POST":
                    response = self.client.post(f"{GITHUB_API_BASE}{path}", **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")

                if response.status_code in (429, 500, 502, 503):
                    retry_after = int(response.headers.get("Retry-After", RETRY_BACKOFF ** (attempt + 1)))
                    logger.warning(f"Rate limited or server error ({response.status_code}), retrying in {retry_after}s")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code == 429:
                    retry_after = int(e.response.headers.get("Retry-After", RETRY_BACKOFF ** (attempt + 1)))
                    logger.warning(f"Rate limited, retrying in {retry_after}s")
                    time.sleep(retry_after)
                    continue
                raise

        raise last_error or Exception("Max retries exceeded")

    def close(self) -> None:
        self.client.close()
