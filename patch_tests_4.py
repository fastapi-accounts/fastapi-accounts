import re

with open("tests/test_audit_remediations.py", "r") as f:
    content = f.read()

content = content.replace(
    'accounts_a = FastAPIAccounts(\n        adapter=None, # type: ignore',
    'from fastapi_accounts.adapters.sqlalchemy import SQLAlchemyAdapter\n    adapter = SQLAlchemyAdapter(database_url="sqlite+aiosqlite:///:memory:")\n    accounts_a = FastAPIAccounts(\n        adapter=adapter,'
)

content = content.replace(
    'accounts_b = FastAPIAccounts(\n        adapter=None, # type: ignore',
    'accounts_b = FastAPIAccounts(\n        adapter=adapter,'
)

with open("tests/test_audit_remediations.py", "w") as f:
    f.write(content)
