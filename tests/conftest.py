"""Collection guard: a test id is copied into the PYTEST_CURRENT_TEST
environment variable, which Windows caps at 32767 characters and Linux at
128 KiB per string for any child process. A long parameter (a whole hostile
paste) as the id broke both. Ids stay short; give such cases an explicit id."""
import pytest

MAX_NODEID = 1_000


def pytest_collection_modifyitems(items):
    long = [f"{item.nodeid[:80]}... ({len(item.nodeid)} chars)" for item in items
            if len(item.nodeid) > MAX_NODEID]
    if long:
        raise pytest.UsageError(f"test ids longer than {MAX_NODEID} characters; "
                                f"give the parameters short ids:\n" + "\n".join(long))
