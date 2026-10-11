import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class MockHandler(BaseHTTPRequestHandler):
    def response(self):
        if self.path.startswith('/cf/zones/'):
            zone_id = urlparse(self.path).path.split('/')[3]
            if self.headers.get('Authorization') != 'Bearer known_Cloudflare_secret_DO_NOT_PERSIST_9876':
                return 403, 'application/json', b'{"success":false}'
            if '/dns_records' in self.path:
                return 200, 'application/json', b'{"success":true,"result":[]}'
            zone_name = 'other.org' if zone_id == 'b' * 32 else 'example.net'
            return 200, 'application/json', json.dumps({'success': True, 'result': {'id': zone_id, 'name': zone_name}}).encode()
        response_format = parse_qs(urlparse(self.path).query).get("format", [""])[0]
        if response_format in ("sources6", "sources5", "sources-base64", "truncated"):
            count = 5 if response_format == "sources5" else 6
            plain = ("剩余流量：88GB\r\n# 公告\r\n\r\n" + "".join(
                f"trojan://password@na{i:03d}.example.com:443?sni=sni.example.com&flag=keep#Node{i}\r\n"
                for i in range(1, count + 1))).encode()
            if response_format == "sources-base64":
                plain = base64.b64encode(plain).rstrip(b"=")
            return 200, "text/plain", plain
        if response_format in ("sources-yaml", "empty-group"):
            nodes = "".join(
                f"  - {{name: Node{i}, type: trojan, server: na{i:03d}.example.com, port: 443, password: secret}}\n"
                for i in range(1, 7))
            refs = "Node6" if response_format == "empty-group" else "Node1, Node2, Node3, Node4, Node5, Node6, DIRECT, REJECT"
            return 200, "application/yaml", (
                "proxies:\n" + nodes + "proxy-groups:\n"
                f"  - {{name: Select, type: select, proxies: [{refs}]}}\n"
                "  - {name: Fallback, type: select, proxies: [Select, DIRECT]}\n"
                "rules: ['MATCH,Select']\n").encode()
        if response_format == "malformed":
            return 200, "text/plain", b"trojan://\n"
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
        if response_format in ("metadata-base64", "unknown-scheme-base64"):
            notes = "  剩余流量：88GB  \r\n套餐到期：2026-12-31\r\n官网：https://website.example.com\r\n" \
                "https://download.example.com\r\n# 公告\r\n\r\n提示：请使用 vless:// 格式客户端\r\n"
            nodes = [f"{'vless' if i % 2 == 0 else 'hysteria2'}://credential@origin.example.invalid:443?sni=origin.example.invalid#Node-{i}\r\n" for i in range(41)]
            plain = (notes + "".join(nodes)).encode()
            if response_format == "unknown-scheme-base64":
                plain += b"anytls://credential@origin.example.invalid:443\r\n"
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
        truncated = parse_qs(urlparse(self.path).query).get("format", [""])[0] == "truncated"
        self.send_header("Content-Length", str(len(body) + (10 if truncated else 0)))
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
