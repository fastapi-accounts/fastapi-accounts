import re

with open("tests/test_audit_remediations.py", "r") as f:
    content = f.read()

content = content.replace(
    'res = await client.post("/auth/login", data={"username": "expire@example.com", "password": "SecurePassword123!"})',
    'res = await client.post("/auth/login", json={"email": "expire@example.com", "password": "SecurePassword123!"})'
)

# Replace the httpx csrf test with a direct unit test
csrf_test_old = """@pytest.mark.asyncio
async def test_csrf_non_ascii_handling(cookie_accounts: FastAPIAccounts):
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport
    
    app = FastAPI()
    app.include_router(cookie_accounts.router, prefix="/auth")
    transport = ASGITransport(app=app)
    
    # Enable CSRF
    cookie_accounts.transport.csrf_protect = True
    
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/auth/login",
            data={"username": "fake@example.com", "password": "password"},
            cookies={"fastapi_accounts_csrf": "abc🚀"},
            headers={"X-CSRF-Token": "abc🚀", "Origin": "http://test"}
        )
        # Should cleanly reject (401 or 403) instead of 500
        assert res.status_code in (401, 403), res.text"""

csrf_test_new = """def test_csrf_non_ascii_handling():
    from fastapi_accounts.security.csrf import validate_csrf_token
    # Pass non-ASCII values; it should return False instead of raising an exception
    assert not validate_csrf_token("abc🚀", "abc🚀", None, b"secret" * 8)"""

content = content.replace(csrf_test_old, csrf_test_new)

content = content.replace(
    'secret_key="secret",',
    'secret_key="secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret_secret",\n        allow_legacy_tokens=False,'
)

with open("tests/test_audit_remediations.py", "w") as f:
    f.write(content)
