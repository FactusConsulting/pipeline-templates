import hashlib
import http.server
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import threading
import urllib.parse

import pytest

import dtrack
from conftest import API_KEY, FAKE_BOM, finding

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "sbom-dependency-track", "dtrack.py")


def closed_port_url():
    """A loopback URL nothing listens on (port 1 may blackhole instead of refusing)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return "http://127.0.0.1:%d" % sock.getsockname()[1]


def parse(*argv):
    return dtrack.build_parser().parse_args(["run", *argv])


@pytest.fixture
def env(tmp_path, monkeypatch):
    summary, output = tmp_path / "summary.md", tmp_path / "output.txt"
    values = {
        dtrack.API_KEY_ENV: API_KEY,
        "GITHUB_REPOSITORY": "FactusConsulting/hotlaps",
        "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(output),
    }
    for key in list(os.environ):
        if key.startswith(("GITHUB_", "DTRACK_")):
            monkeypatch.delenv(key)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return {"summary": summary, "output": output, "tmp": tmp_path}


def run_args(dt, fake_syft, env, *extra):
    return parse("--image", "ghcr.io/factusconsulting/hotlaps-api:1.2.3@sha256:" + "a" * 64,
                 "--url", dt.url, "--syft", fake_syft, "--sbom-out", str(env["tmp"] / "sbom.json"),
                 "--poll-interval", "0.01", "--retry-delay", "0.01", "--parent-wait", "0.3", "--import-wait", "5", *extra)


def outputs(env):
    return dict(line.split("=", 1) for line in env["output"].read_text().splitlines())


# ── input resolution ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("ref,expected", [
    ("ghcr.io/org/app:1.2", ("ghcr.io/org/app", "1.2", "")),
    ("ghcr.io/org/app@sha256:abc", ("ghcr.io/org/app", "", "sha256:abc")),
    ("ghcr.io/org/app:v1@sha256:abc", ("ghcr.io/org/app", "v1", "sha256:abc")),
    ("localhost:5000/app", ("localhost:5000/app", "", "")),
    ("localhost:5000/app:dev", ("localhost:5000/app", "dev", "")),
    ("myimage:dev", ("myimage", "dev", "")),
    ("myimage", ("myimage", "", "")),
    ("docker:myimage:dev", ("myimage", "dev", "")),
])
def test_split_image(ref, expected):
    assert dtrack.split_image(ref) == expected


def test_defaults_from_environment(env):
    s = dtrack.resolve_settings(parse("--image", "ghcr.io/o/app:1.2"), os.environ)
    assert (s["project"], s["version"], s["parent"], s["tags"]) == (
        "build/hotlaps/app", "1.2", "build/hotlaps", ["build"])
    assert s["url"] == dtrack.DEFAULT_URL


def test_version_falls_back_to_short_sha_for_digest_only_ref(env):
    s = dtrack.resolve_settings(parse("--image", "ghcr.io/o/app@sha256:" + "b" * 64), os.environ)
    assert s["version"] == "0123456"


def test_explicit_values_win(env):
    s = dtrack.resolve_settings(parse("--image", "app:1", "--project", "p", "--version", "9",
                                      "--parent", "x/y", "--fail-on-severity", "high"), os.environ)
    assert (s["project"], s["version"], s["parent"], s["floor"]) == ("p", "9", "x/y", "HIGH")


@pytest.mark.parametrize("extra", [["--fail-on-severity", "SEVERE"], ["--wait-timeout", "abc"],
                                   ["--wait-timeout", "0"], ["--url", "ftp://x"]])
def test_invalid_input(env, extra):
    with pytest.raises(dtrack.ConfigError):
        dtrack.resolve_settings(parse("--image", "app:1", *extra), os.environ)


def test_syft_target_pins_digest_to_registry():
    assert dtrack.syft_target("ghcr.io/o/a:1@sha256:abc") == "registry:ghcr.io/o/a:1@sha256:abc"
    assert dtrack.syft_target("ghcr.io/o/a:1") == "ghcr.io/o/a:1"
    assert dtrack.syft_target("docker:a:1") == "docker:a:1"


# ── BOM slimming ─────────────────────────────────────────────────────────────


def test_slim_bom_drops_files_duplicates_and_bulky_properties():
    bom = dtrack.slim_bom(json.loads(json.dumps(FAKE_BOM)))
    assert [c["bom-ref"] for c in bom["components"]] == ["pkg-a"]
    assert bom["components"][0]["properties"] == [{"name": "syft:package:type", "value": "deb"}]
    assert bom["dependencies"] == [{"ref": "root", "dependsOn": ["pkg-a"]}]
    assert not any(c["type"] == "file" for c in bom["components"])


@pytest.mark.parametrize("purl", [
    "pkg:nuget/" + "%FFFFFFC3%FFFFFF90" * 5 + "@74.1.2509.2501",   # sign-extended garbage escapes
    "pkg:nuget/abc%ZZdef@1",                                         # invalid percent escape
    "pkg:nuget/abc%2@1",                                             # truncated escape
    "pkg:nuget/ab\x07c@1",                                           # control character
    "pkg:nuget/" + "a" * 1100 + "@1",                                # over-long
])
def test_garbage_purls_are_dropped(purl, capsys):
    bom = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "bom-ref": "ok", "name": "fine", "version": "1", "purl": "pkg:nuget/Fine%C3%A9@1"},
        {"type": "library", "bom-ref": "bad", "name": "x", "version": "1", "purl": purl}]}
    assert [c["bom-ref"] for c in dtrack.slim_bom(bom)["components"]] == ["ok"]
    out = capsys.readouterr().out
    assert "::warning" in out and "dropped 1 component(s) DT cannot store" in out
    assert len(out) < 600  # the example is truncated


def test_purl_short_raw_but_too_long_once_dt_reencodes_it_is_dropped(capsys):
    # Like the hotlaps test-runtime nuget component: valid UTF-8 mojibake, < 1024 chars raw,
    # but DT stores every non-ASCII byte as %FFFFFFxx (9 chars) and overflows the column.
    for purl in ("pkg:nuget/" + "%C3%90" * 150 + "@74.1.2509.2501", "pkg:nuget/" + "Ð" * 150 + "@74.1.2509.2501"):
        assert len(purl) < 1024 < dtrack.projected_purl_length(purl)
        bom = {"bomFormat": "CycloneDX", "components": [
            {"type": "library", "bom-ref": "bad", "name": "Ð" * 150, "version": "74.1.2509.2501", "purl": purl}]}
        assert dtrack.slim_bom(bom)["components"] == []
        assert "dropped 1 component(s) DT cannot store" in capsys.readouterr().out


def test_real_hotlaps_purl_is_dropped():
    # The purl DT rejected (226 chars raw); it projects to ~1083 under DT's double encoding.
    name = "Средства Visual Studio для контейнеров — общие"
    purl = "pkg:nuget/" + urllib.parse.quote(name, safe="") + "@74.1.2509.2501"
    assert len(purl) < 300 and dtrack.projected_purl_length(purl) > 1024
    bom = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "bom-ref": "ru", "name": name, "version": "74.1.2509.2501", "purl": purl},
        {"type": "library", "bom-ref": "ok", "name": "Microsoft.VisualStudio.Containers.Tools.Common",
         "version": "74.1.2509.2501",
         "purl": "pkg:nuget/Microsoft.VisualStudio.Containers.Tools.Common@74.1.2509.2501"}]}
    assert [c["bom-ref"] for c in dtrack.slim_bom(bom)["components"]] == ["ok"]


def test_short_non_ascii_purls_are_kept_and_projection_counts_bytes():
    assert dtrack.projected_purl_length("pkg:nuget/abc@1.0") == len("pkg:nuget/abc@1.0") + 2  # '@' escapes to 3
    assert dtrack.projected_purl_length("pkg:nuget/Caf%C3%A9@1") == len("pkg:nuget/Caf") + 2 * 18 + 3 + 1
    bom = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "bom-ref": "ok", "name": "Café", "version": "1", "purl": "pkg:nuget/Caf%C3%A9@1"},
        {"type": "library", "bom-ref": "ok2", "name": "日本語", "version": "1", "purl": "pkg:nuget/日本語@1"}]}
    assert [c["bom-ref"] for c in dtrack.slim_bom(bom)["components"]] == ["ok", "ok2"]


def test_dropped_example_is_truncated_to_120_chars(capsys):
    bom = {"bomFormat": "CycloneDX", "components": [
        {"type": "library", "bom-ref": "bad", "name": "x", "purl": "pkg:nuget/" + "a" * 2000 + "@1"}]}
    dtrack.slim_bom(bom)
    out = capsys.readouterr().out
    assert "a" * 100 in out and "a" * 121 not in out


def test_slim_bom_drops_components_dt_cannot_store(capsys):
    bom = json.loads(json.dumps(FAKE_BOM))
    bom["components"] += [
        {"type": "library", "bom-ref": "bad-purl", "name": "x", "version": "74.1.2509.2501",
         "purl": "pkg:nuget/" + "%FFFFFFC3%FFFFFF90" * 80 + "@74.1.2509.2501"},
        {"type": "library", "bom-ref": "bad-name", "name": "n" * 256, "version": "1"},
    ]
    bom["dependencies"].append({"ref": "bad-purl", "dependsOn": []})
    slim = dtrack.slim_bom(bom)
    assert [c["bom-ref"] for c in slim["components"]] == ["pkg-a"]
    assert all(d["ref"] != "bad-purl" for d in slim["dependencies"])
    assert "dropped 2 component(s) DT cannot store" in capsys.readouterr().out


# ── syft install ─────────────────────────────────────────────────────────────


def tarball(content=b"#!/bin/sh\necho syft\n"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("syft")
        info.size = len(content)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


@pytest.fixture
def release_server():
    blob = tarball()
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % server.server_address[1], blob, hits
    server.shutdown()
    server.server_close()


def test_install_syft_verifies_checksum_and_caches(tmp_path, release_server):
    base, blob, hits = release_server
    sums = {"amd64": hashlib.sha256(blob).hexdigest()}
    path = dtrack.install_syft(str(tmp_path), "9.9.9", sums, base, "amd64")
    assert os.access(path, os.X_OK) and open(path, "rb").read().startswith(b"#!/bin/sh")
    assert hits == ["/v9.9.9/syft_9.9.9_linux_amd64.tar.gz"]
    assert dtrack.install_syft(str(tmp_path), "9.9.9", sums, base, "amd64") == path
    assert len(hits) == 1  # cached, not downloaded again


def test_install_syft_rejects_checksum_mismatch(tmp_path, release_server):
    base, _, _ = release_server
    with pytest.raises(dtrack.SoftError, match="checksum mismatch"):
        dtrack.install_syft(str(tmp_path), "9.9.9", {"amd64": "0" * 64}, base, "amd64")
    assert not list(tmp_path.iterdir())


def test_install_syft_unreachable(tmp_path):
    with pytest.raises(dtrack.SoftError, match="cannot download syft"):
        dtrack.install_syft(str(tmp_path), "9.9.9", {"amd64": "0" * 64}, closed_port_url(), "amd64")


def test_pinned_syft_table_covers_both_arches():
    assert set(dtrack.SYFT_SHA256) == {"amd64", "arm64"}
    assert all(len(h) == 64 for h in dtrack.SYFT_SHA256.values())
    assert dtrack.syft_arch("x86_64") == "amd64" and dtrack.syft_arch("aarch64") == "arm64"
    with pytest.raises(dtrack.SoftError):
        dtrack.syft_arch("riscv64")


# ── upload flow ──────────────────────────────────────────────────────────────


def test_upload_order_body_and_key_header(dt, fake_syft, env, capsys):
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    puts = dt.uploads
    assert [(p[3]["projectName"], p[3].get("parentName")) for p in puts] == [
        ("build", None), ("build/hotlaps", "build"), ("build/hotlaps/hotlaps-api", "build/hotlaps")]
    assert puts[1][3]["parentVersion"] == dtrack.PARENT_VERSION
    assert all(p[3]["autoCreate"] is True for p in puts)
    assert all(p[4]["X-Api-Key"] == API_KEY for p in dt.requests)

    parent_bom = dt.decode_bom(puts[0][3])
    assert parent_bom["components"] == []

    project = puts[2][3]
    assert project["projectVersion"] == "1.2.3"
    assert project["projectTags"] == [{"name": "build"}]
    bom = dt.decode_bom(project)  # base64 of CycloneDX JSON
    assert bom["bomFormat"] == "CycloneDX"
    assert [c["bom-ref"] for c in bom["components"]] == ["pkg-a"]
    # the pushed manifest is scanned, not whatever the local daemon has under that tag
    assert open(env["tmp"] / "syft-args.txt").read().startswith("registry:ghcr.io/factusconsulting/hotlaps-api:1.2.3@sha256:")

    # parents were processed (token polled) before the project upload
    kinds = ["PUT" if r[0] == "PUT" else "poll" for r in dt.requests]
    assert kinds[0] == "PUT" and kinds.count("PUT") == 3
    assert kinds[-1] == "poll"  # the image import is verified even in report-only mode
    assert all(k == "poll" for k in kinds[1:kinds.index("PUT", 1)])  # first parent polled before the next upload
    assert kinds[kinds.index("PUT", 1) + 1] == "poll"                 # ...and so was the second
    out = capsys.readouterr()
    assert API_KEY not in out.out + out.err
    assert API_KEY not in env["summary"].read_text() + env["output"].read_text()
    o = outputs(env)
    assert o["gate"] == "skipped" and o["project"] == "build/hotlaps/hotlaps-api" and o["imported"] == "true"
    assert json.loads(open(o["sbom-path"]).read())["components"][0]["name"] == "openssl"


def test_report_only_does_not_poll_the_project_token(dt, fake_syft, env):
    dt.findings = [finding("CVE-1", "CRITICAL")]
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    assert not any(r[1].startswith("/api/v1/finding") for r in dt.requests)
    assert outputs(env)["gate"] == "skipped"


def test_custom_project_and_parent_chain(dt, fake_syft, env):
    assert dtrack.run(run_args(dt, fake_syft, env, "--project", "k8s/ns/app", "--parent", "k8s/ns",
                               "--version", "v7")) == 0
    assert [(p[3]["projectName"], p[3].get("parentName")) for p in dt.uploads] == [
        ("k8s", None), ("k8s/ns", "k8s"), ("k8s/ns/app", "k8s/ns")]
    assert dt.uploads[-1][3]["projectVersion"] == "v7"


# ── gate ─────────────────────────────────────────────────────────────────────


def test_gate_passes_when_only_below_floor_or_suppressed(dt, fake_syft, env, capsys):
    dt.findings = [finding("CVE-1", "MEDIUM"), finding("CVE-2", "CRITICAL", suppressed=True)]
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "HIGH")) == 0
    o = outputs(env)
    assert o["gate"] == "passed" and o["findings-blocking"] == "0" and o["findings-total"] == "1"
    summary = env["summary"].read_text()
    assert "CVE-1" in summary and "CVE-2" not in summary
    assert dt.polls > 2  # waited for processing=false
    assert API_KEY not in capsys.readouterr().out


def test_gate_fails_at_floor_and_writes_summary(dt, fake_syft, env, capsys):
    dt.findings = [finding("CVE-3", "HIGH", epss=0.5), finding("CVE-4", "LOW"), finding("CVE-5", "CRITICAL")]
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "high")) == 1
    o = outputs(env)
    assert o["gate"] == "failed" and o["findings-blocking"] == "2" and o["project-uuid"] == "uuid-1"
    summary = env["summary"].read_text()
    assert "| CRITICAL | 1 |" in summary and "gate FAILED" in summary
    assert summary.index("CVE-5") < summary.index("CVE-3") < summary.index("CVE-4")  # worst first
    out = capsys.readouterr().out
    assert "::error" in out and "CVE-5" in out and API_KEY not in out


def test_gate_floor_low_catches_low(dt, fake_syft, env):
    dt.findings = [finding("CVE-4", "LOW")]
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "LOW")) == 1


def test_gate_unassigned_never_blocks(dt, fake_syft, env):
    dt.findings = [finding("CVE-6", "UNASSIGNED"), finding("CVE-7", "INFO")]
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "LOW")) == 0


def test_findings_are_paginated(dt, fake_syft, env):
    dt.page_size_cap = 2
    dt.findings = [finding("CVE-%d" % i, "LOW") for i in range(5)] + [finding("CVE-X", "CRITICAL")]
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "CRITICAL")) == 1
    pages = [r[2]["pageNumber"] for r in dt.requests if r[1].startswith("/api/v1/finding")]
    assert pages == ["1", "2", "3"]
    assert outputs(env)["findings-total"] == "6"


def test_wait_timeout_fails_closed(dt, fake_syft, env, capsys):
    dt.processing_polls = 10 ** 9
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "HIGH", "--wait-timeout", "0.2")) == 1
    out = capsys.readouterr().out
    assert "still processing" in out and "failing closed" in out
    assert outputs(env)["gate"] == "unavailable"


# ── failure policy ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("fail_put", [(503, "down"), (401, "bad key")])
def test_dt_failure_does_not_fail_report_only_build(dt, fake_syft, env, capsys, fail_put):
    dt.fail_put = fail_put
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    out = capsys.readouterr().out
    assert "::warning" in out and "build is not affected" in out
    assert outputs(env)["gate"] == "skipped"


def test_dt_failure_fails_closed_with_floor(dt, fake_syft, env, capsys):
    dt.fail_put = (503, "down")
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "HIGH")) == 1
    out = capsys.readouterr().out
    assert "::error" in out and "failing closed" in out
    assert "FAILED" in env["summary"].read_text()


def test_unreachable_dt(fake_syft, env, capsys):
    args = parse("--image", "app:1", "--url", closed_port_url(), "--syft", fake_syft,
                 "--sbom-out", str(env["tmp"] / "s.json"), "--retry-delay", "0.01", "--upload-attempts", "2")
    assert dtrack.run(args) == 0
    assert "cannot reach" in capsys.readouterr().out
    args.fail_on_severity = "HIGH"
    assert dtrack.run(args) == 1


def test_5xx_is_retried_then_succeeds(dt, fake_syft, env):
    dt.fail_put = (503, "down")
    args = run_args(dt, fake_syft, env, "--upload-attempts", "50")
    threading.Timer(0.1, lambda: setattr(dt, "fail_put", None)).start()
    assert dtrack.run(args) == 0
    assert dt.uploads[-1][3]["projectName"] == "build/hotlaps/hotlaps-api"
    assert sum(1 for p in dt.uploads if p[3]["projectName"] == "build") > 1  # first parent upload was retried


def test_error_body_echoing_the_key_is_scrubbed(dt, fake_syft, env, capsys):
    dt.fail_put = (400, "rejected key " + API_KEY)
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    out = capsys.readouterr().out
    assert API_KEY not in out and "***" in out


def test_syft_failure_follows_same_policy(dt, env, tmp_path, capsys):
    broken = tmp_path / "broken-syft"
    broken.write_text("#!/bin/sh\necho boom >&2\nexit 3\n")
    broken.chmod(0o755)
    args = parse("--image", "app:1", "--url", dt.url, "--syft", str(broken),
                 "--sbom-out", str(env["tmp"] / "s.json"))
    assert dtrack.run(args) == 0
    assert "syft failed (exit 3): boom" in capsys.readouterr().out
    assert dt.requests == []
    args.fail_on_severity = "HIGH"
    assert dtrack.run(args) == 1


def test_missing_api_key(dt, fake_syft, env, monkeypatch, capsys):
    monkeypatch.delenv(dtrack.API_KEY_ENV)
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    assert "::warning" in capsys.readouterr().out and dt.requests == []
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "HIGH")) == 1


def test_invalid_input_exits_2(dt, fake_syft, env):
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "SEVERE")) == 2
    assert dt.requests == []


# ── the real CLI, as the action invokes it ───────────────────────────────────


def cli(dt, fake_syft, env, *extra):
    environ = dict(os.environ)
    return subprocess.run(
        [sys.executable, SCRIPT, "run", "--image", "ghcr.io/o/app:1", "--url", dt.url, "--syft", fake_syft,
         "--sbom-out", str(env["tmp"] / "cli-sbom.json"), "--poll-interval", "0.01", *extra],
        env=environ, capture_output=True, text=True)


def test_cli_end_to_end_never_prints_the_key(dt, fake_syft, env):
    dt.findings = [finding("CVE-9", "HIGH")]
    failed = cli(dt, fake_syft, env, "--fail-on-severity", "HIGH")
    assert failed.returncode == 1
    dt.polls = 0
    dt.findings = []
    passed = cli(dt, fake_syft, env, "--fail-on-severity", "HIGH")
    assert passed.returncode == 0
    for result in (failed, passed):
        assert API_KEY not in result.stdout + result.stderr
    assert API_KEY not in env["summary"].read_text() + env["output"].read_text()
    assert "gate passed" in env["summary"].read_text()


def test_cli_unexpected_error_does_not_leak_key(dt, fake_syft, env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaboom " + API_KEY)

    monkeypatch.setattr(dtrack, "run", boom)
    rc = dtrack.main(["run", "--image", "app:1"])
    assert rc == 0


def test_wait_timeout_accepts_seconds_suffix(env):
    s = dtrack.resolve_settings(parse("--image", "app:1", "--wait-timeout", "120s"), os.environ)
    assert s["wait_timeout"] == 120.0


def test_digest_ref_output_for_attestation(dt, fake_syft, env):
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    assert outputs(env)["image-digest-ref"] == "ghcr.io/factusconsulting/hotlaps-api@sha256:" + "a" * 64


# ── import verification ──────────────────────────────────────────────────────


def test_failed_import_warns_in_report_only_mode(dt, fake_syft, env, capsys):
    dt.last_bom_import = None
    dt.component_total = 0
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    out = capsys.readouterr().out
    assert "::warning" in out and "DT did not import the BOM" in out and "lastBomImport" in out
    o = outputs(env)
    assert o["imported"] == "false" and o["gate"] == "skipped"
    assert "NOT imported" in env["summary"].read_text()


def test_zero_components_despite_import_timestamp_warns(dt, fake_syft, env, capsys):
    dt.component_total = 0
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    assert "has 0 components but the SBOM had 1" in capsys.readouterr().out
    assert outputs(env)["imported"] == "false"
    assert any(r[1] == "/api/v1/component/project/uuid-1" and r[2]["pageSize"] == "1" for r in dt.requests)


def test_failed_import_fails_the_gate(dt, fake_syft, env, capsys):
    dt.last_bom_import = None
    dt.component_total = 0
    assert dtrack.run(run_args(dt, fake_syft, env, "--fail-on-severity", "HIGH")) == 1
    out = capsys.readouterr().out
    assert "::error" in out and "DT did not import the BOM" in out and "failing closed" in out
    assert outputs(env)["imported"] == "false"
    assert not any(r[1].startswith("/api/v1/finding") for r in dt.requests)


def test_empty_bom_only_needs_an_import_timestamp(dt, env, tmp_path):
    empty = tmp_path / "empty-syft"
    empty.write_text("#!%s\nimport sys, json\nout = sys.argv[sys.argv.index('-o') + 1].split('=', 1)[1]\n"
                     "json.dump({'bomFormat': 'CycloneDX', 'components': []}, open(out, 'w'))\n" % sys.executable)
    empty.chmod(0o755)
    dt.component_total = 0
    args = parse("--image", "app:1", "--url", dt.url, "--syft", str(empty), "--sbom-out", str(env["tmp"] / "s.json"),
                 "--poll-interval", "0.01", "--parent-wait", "0.3")
    assert dtrack.run(args) == 0
    assert outputs(env)["imported"] == "true"
    assert not any(r[1].startswith("/api/v1/component") for r in dt.requests)


def test_import_wait_timeout_is_unknown_not_failure(dt, fake_syft, env, capsys):
    dt.processing_polls = 10 ** 9
    assert dtrack.run(run_args(dt, fake_syft, env, "--import-wait", "0.2")) == 0
    out = capsys.readouterr().out
    assert "::warning" in out and "could not confirm DT imported the BOM" in out
    assert outputs(env)["imported"] == "unknown"


def test_dt_outage_during_import_check_stays_a_warning(dt, fake_syft, env, capsys):
    dt.token_status = 503
    assert dtrack.run(run_args(dt, fake_syft, env, "--import-wait", "0.2")) == 0
    assert "could not confirm DT imported the BOM" in capsys.readouterr().out
    assert outputs(env)["imported"] == "unknown"


def test_not_uploaded_means_not_imported(dt, fake_syft, env):
    dt.fail_put = (503, "down")
    assert dtrack.run(run_args(dt, fake_syft, env)) == 0
    assert outputs(env)["imported"] == "false"


def test_import_wait_accepts_seconds_suffix_and_rejects_garbage(env):
    assert dtrack.resolve_settings(parse("--image", "a:1", "--import-wait", "90s"), os.environ)["import_wait"] == 90.0
    with pytest.raises(dtrack.ConfigError):
        dtrack.resolve_settings(parse("--image", "a:1", "--import-wait", "-1"), os.environ)
