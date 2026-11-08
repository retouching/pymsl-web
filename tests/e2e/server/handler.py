from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from tests.e2e.server.msl_server import MSLServer


class Handler(BaseHTTPRequestHandler):
    server_state = MSLServer()

    def do_GET(self) -> None:
        """Answer the health check and give the server's public key."""
        if self.path == "/health":
            self.reply(HTTPStatus.OK, b"ok")
        elif self.path == "/key":
            self.reply(HTTPStatus.OK, self.server_state.crypto.public_pem())
        else:
            self.reply(HTTPStatus.NOT_FOUND, b"")

    def do_POST(self) -> None:
        """Answer an MSL message posted on /msl."""
        if not self.path.startswith("/msl"):
            self.reply(HTTPStatus.NOT_FOUND, b"")
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            json_echo = self.path.split("?")[0] == "/msl/json"
            self.reply(HTTPStatus.OK, self.server_state.answer(body, json_echo=json_echo))
        except KeyError, TypeError, ValueError:
            self.reply(HTTPStatus.BAD_REQUEST, b"")

    def reply(self, status: HTTPStatus, body: bytes) -> None:
        """Send `body` with `status`."""
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
