import secrets
import shutil
from collections.abc import Iterator

import pytest

from tests.e2e.stack import ROOT, Stack


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    """Put the temporary folders of pytest in `.e2e-tmp/` of the repository when no `--basetemp` is given."""
    if config.option.basetemp is None:
        config.option.basetemp = str(ROOT / ".e2e-tmp")


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove the temporary folders of pytest at the end of the session, even after a failure."""
    shutil.rmtree(config.option.basetemp, ignore_errors=True)


@pytest.fixture(scope="session")
def stack() -> Iterator[Stack]:
    """Start the stack of the session, then remove it and fail on any object it leaves."""
    stack = Stack(project=f"pymsl-web-e2e-{secrets.token_hex(4)}")
    try:
        stack.start()
        yield stack
    finally:
        stack.remove()
        leftovers = stack.leftovers()
        if leftovers:
            pytest.fail(f"The stack {stack.project} left {', '.join(leftovers)}.", pytrace=False)
