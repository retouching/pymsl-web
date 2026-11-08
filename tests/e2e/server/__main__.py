from http.server import ThreadingHTTPServer

from tests.e2e.server.handler import Handler


class Main:
    @staticmethod
    def run() -> None:
        """Serve the fake MSL server on port 8080."""
        ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104


Main.run()
