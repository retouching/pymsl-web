import socket
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError


class TestGuard:
    def test_blocks_tcp(self) -> None:
        """Refuse a TCP socket in a unit test."""
        with pytest.raises(SocketBlockedError):
            socket.create_connection(("127.0.0.1", 9))

    def test_moves_home(self, tmp_path: Path) -> None:
        """Put HOME and the current directory in the temporary folder of the test."""
        assert Path.home() == tmp_path
        assert Path.cwd() == tmp_path
