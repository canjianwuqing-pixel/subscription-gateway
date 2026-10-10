import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class MockHandler(BaseHTTPRequestHandler):
    def response(self):
        response_format = parse_qs(urlparse(self.path).query).get("format", [""])[0]
        if response_format == "new-source":
            return 200, "text/plain", (
                b"trojan://password@new.example.invalid:443?sni=sni-only.example.invalid#name-only.example.invalid\n"
            )
        if response_format == "uri":
            return 200, "text/plain", (
                b"vless://uuid@origin.example.invalid:443?security=reality&"
                b"sni=origin.example.invalid&pbk=key&sid=01#CI-Node\n"
            )
        if response_format == "yaml":
            return 200, "application/yaml", (
                b"proxies:\n"
                b"  - name: CI Node\n"
                b"    type: vless\n"
                b"    server: origin.example.invalid\n"
                b"    port: 443\n"
                b"    uuid: 01234567-89ab-cdef-0123-456789abcdef\n"
                b"    sni: origin.example.invalid\n"
            )
        if response_format == "base64":
            plain = b"trojan://password@origin.example.invalid:443?sni=origin.example.invalid#CI\n"
            return 200, "text/plain", base64.b64encode(plain).rstrip(b"=")
        if response_format == "unknown":
            return 200, "text/plain", b"not a supported subscription document\n"
        if response_format == "unauthorized":
            return 401, "text/plain", b"UPSTREAM_UNAUTHORIZED\n"
        if response_format == "redirect":
            return 302, "text/plain", b"UPSTREAM_REDIRECT\n"
        if response_format == "large":
            return 200, "application/octet-stream", b"L" * (8 * 1024 * 1024 + 1)
        return 200, "text/plain", b"SGW_CI_MOCK_OK\n"

    def do_GET(self):
        status, content_type, body = self.response()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if status == 302:
            self.send_header("Location", "http://redirect-target.example.invalid/subscription")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        status, content_type, body = self.response()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if status == 302:
            self.send_header("Location", "http://redirect-target.example.invalid/subscription")
        self.end_headers()

    def log_message(self, _format, *_args):
        # Query strings can contain test Tokens; do not send them to Docker logs.
        pass


HTTPServer(("0.0.0.0", 8080), MockHandler).serve_forever()
