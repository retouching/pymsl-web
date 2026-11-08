from pymsl_web.session.clock import Clock


class TestClock:
    def test_gives_local_time_unsynchronized(self) -> None:
        """Give the local time before any answer."""
        assert Clock(source=lambda: 1000.7).now() == 1000

    def test_follows_server(self) -> None:
        """Give the server's time once synchronized on an answer's timestamp."""
        clock = Clock(source=lambda: 1000.0)
        clock.synchronize(1300)
        assert clock.offset == 300
        assert clock.now() == 1300
        assert clock.local() == 1000

    def test_follows_server_behind(self) -> None:
        """Follow a server whose clock is behind the local one."""
        clock = Clock(source=lambda: 1000.0)
        clock.synchronize(900)
        assert clock.now() == 900
