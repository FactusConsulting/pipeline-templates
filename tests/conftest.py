import base64
import http.server
import json
import os
import stat
import sys
import threading
import urllib.parse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sbom-dependency-track"))

# A fixture, not a credential; assembled so secret scanners don't flag it.
API_KEY = "odt_" + "fixture" * 4

FAKE_BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {"component": {"bom-ref": "root", "type": "container", "name": "img"}},
    "components": [
        {"type": "library", "bom-ref": "pkg-a", "name": "openssl", "version": "3.0.1",
         "purl": "pkg:deb/debian/openssl@3.0.1",
         "properties": [{"name": "syft:package:type", "value": "deb"},
                        {"name": "syft:location:0:path", "value": "/var/lib/dpkg/status"}]},
        {"type": "library", "bom-ref": "pkg-a-dup", "name": "openssl", "version": "3.0.1",
         "purl": "pkg:deb/debian/openssl@3.0.1"},
        {"type": "file", "bom-ref": "file-1", "name": "/etc/passwd"},
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["pkg-a", "file-1"]}, {"ref": "file-1"}],
}


class StubDT:
    """Minimal Dependency-Track API double that records every request."""

    def __init__(self, api_key=API_KEY):
        self.api_key = api_key
        self.requests = []          # (method, path, query dict, parsed body or None, headers)
        self.processing_polls = 2   # event/token answers processing:true this many times
        self.findings = []
        self.page_size_cap = None
        self.fail_put = None        # (status, body) returned for every PUT /bom
        self.token_status = 200
        self.last_bom_import = 1700000000000   # None = DT never imported the BOM
        self.component_total = 1
        self.polls = 0
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload=None, headers=None, raw=None):
                body = raw if raw is not None else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _handle(self, method):
                parsed = urllib.parse.urlparse(self.path)
                query = dict(urllib.parse.parse_qsl(parsed.query))
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                stub.requests.append((method, parsed.path, query, body, dict(self.headers)))
                if self.headers.get("X-Api-Key") != stub.api_key:
                    return self._send(401, {"error": "bad key %s" % self.headers.get("X-Api-Key")})
                if method == "PUT" and parsed.path == "/api/v1/bom":
                    if stub.fail_put:
                        return self._send(stub.fail_put[0], raw=stub.fail_put[1].encode())
                    return self._send(200, {"token": "tok-%d" % len(stub.requests)})
                if parsed.path.startswith("/api/v1/event/token/"):
                    stub.polls += 1
                    if stub.token_status != 200:
                        return self._send(stub.token_status, {"error": "nope"})
                    return self._send(200, {"processing": stub.polls <= stub.processing_polls})
                if parsed.path == "/api/v1/project/lookup":
                    return self._send(200, {"uuid": "uuid-1", "name": query.get("name"),
                                            "version": query.get("version"),
                                            "lastBomImport": stub.last_bom_import})
                if parsed.path == "/api/v1/component/project/uuid-1":
                    return self._send(200, [{"name": "c"}] * min(stub.component_total, 1),
                                      headers={"X-Total-Count": str(stub.component_total)})
                if parsed.path == "/api/v1/finding/project/uuid-1":
                    size = int(query.get("pageSize", 100))
                    if stub.page_size_cap:
                        size = min(size, stub.page_size_cap)
                    start = (int(query.get("pageNumber", 1)) - 1) * size
                    return self._send(200, stub.findings[start:start + size],
                                      headers={"X-Total-Count": str(len(stub.findings))})
                return self._send(404, {"error": "unknown"})

            def do_PUT(self):
                self._handle("PUT")

            def do_GET(self):
                self._handle("GET")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def uploads(self):
        return [r for r in self.requests if r[0] == "PUT"]

    @staticmethod
    def decode_bom(body):
        return json.loads(base64.b64decode(body["bom"]))


def finding(vuln_id, severity, name="openssl", version="3.0.1", suppressed=False, epss=0.01):
    return {
        "component": {"name": name, "version": version, "purl": "pkg:deb/debian/%s@%s" % (name, version)},
        "vulnerability": {"vulnId": vuln_id, "source": "NVD", "severity": severity, "aliases": [],
                          "epssScore": epss},
        "analysis": {"isSuppressed": suppressed},
    }


@pytest.fixture
def dt():
    stub = StubDT()
    yield stub
    stub.close()


@pytest.fixture
def fake_syft(tmp_path):
    """An executable that mimics `syft <image> -q -o cyclonedx-json=<path>`."""
    bom = tmp_path / "fake-bom.json"
    bom.write_text(json.dumps(FAKE_BOM))
    script = tmp_path / "fake-syft"
    script.write_text(
        "#!%s\nimport shutil, sys\n"
        "out = sys.argv[sys.argv.index('-o') + 1].split('=', 1)[1]\n"
        "open(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        "shutil.copy(%r, out)\n" % (sys.executable, str(tmp_path / "syft-args.txt"), str(bom)))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)
