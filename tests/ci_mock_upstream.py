from http.server import BaseHTTPRequestHandler, HTTPServer


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"SGW_CI_MOCK_OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        # Query strings can contain test Tokens; do not send them to Docker logs.
        pass


HTTPServer(("0.0.0.0", 8080), MockHandler).serve_forever()
