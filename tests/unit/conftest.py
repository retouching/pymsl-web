from collections.abc import Iterator
from pathlib import Path

import pytest
from pytest_socket import disable_socket, enable_socket, socket_allow_hosts


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Block TCP and UDP sockets before each unit test, but a test marked `enable_socket`, which may open them on
    127.0.0.1 alone."""
    if item.get_closest_marker("enable_socket") is None:
        disable_socket(allow_unix_socket=True)
    else:
        enable_socket()
        socket_allow_hosts(["127.0.0.1"], allow_unix_socket=True)


@pytest.fixture(autouse=True)
def isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Move the current directory and HOME into the temporary folder of the test."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    yield
    enable_socket()
