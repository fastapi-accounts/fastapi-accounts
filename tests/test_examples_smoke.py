import os

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault(
    "FASTAPI_ACCOUNTS_SECRET_KEY",
    "strong-test-secret-key-32-chars-long-for-smoke-testing-only-12345",
)

from examples.basic_app import app


@pytest.mark.asyncio
async def test_example_basic_app_smoke():
    """Verify that examples/basic_app.py loads cleanly and responds to basic endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Protected route without auth should return 401
        resp = await client.get("/api/v1/profile")
        assert resp.status_code == 401
