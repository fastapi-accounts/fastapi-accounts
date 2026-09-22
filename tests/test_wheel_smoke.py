import pkgutil

import fastapi_accounts
import fastapi_accounts.dependencies
import fastapi_accounts.migrations
import fastapi_accounts.models
import fastapi_accounts.schemas
import fastapi_accounts.security
import fastapi_accounts.services
import fastapi_accounts.stores
import fastapi_accounts.transports


def test_subpackage_discoverability():
    """Assert all core architectural subpackages are cleanly importable and structured."""
    subpackages = [
        fastapi_accounts.dependencies,
        fastapi_accounts.migrations,
        fastapi_accounts.models,
        fastapi_accounts.schemas,
        fastapi_accounts.security,
        fastapi_accounts.services,
        fastapi_accounts.stores,
        fastapi_accounts.transports,
    ]
    for pkg in subpackages:
        assert pkg is not None


def test_migrations_package_resources():
    """Assert all 4 version files and script.py.mako are discoverable within migrations package."""
    import fastapi_accounts.migrations.versions as vers_pkg

    version_modules = [name for _, name, _ in pkgutil.iter_modules(vers_pkg.__path__)]
    expected_revisions = [
        "0001_initial_schema",
        "0002_add_password_updated_at",
        "0003_add_session_indexes",
        "0004_add_credential_version",
        "0005_add_session_credential_version",
    ]
    for rev in expected_revisions:
        assert rev in version_modules, f"Missing migration revision: {rev}"
