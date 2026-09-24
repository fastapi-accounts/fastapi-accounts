import re

with open("tests/test_audit_remediations.py", "r") as f:
    content = f.read()

# Fix expire on commit login JSON/Form
content = content.replace(
    'res = await client.post("/auth/login", data={"username": "expire@example.com", "password": "SecurePassword123!"})',
    'res = await client.post("/auth/login", data={"username": "expire@example.com", "password": "SecurePassword123!"})'
)
# Wait, why did the route complain? Because in FastAPI Accounts the login endpoint might take JSON! Let's check how login is tested elsewhere.
