#!/usr/bin/env python3
"""Build-time SBOM -> Dependency-Track, with an optional vulnerability gate.

One stdlib-only script behind the ``sbom-dependency-track`` composite action:

1. fetch a pinned, checksum-verified syft (unless ``--syft`` points at one),
2. ``syft <image> -o cyclonedx-json`` and slim the BOM (no ``file`` components),
3. create the grouping parents (``build`` -> ``build/<repo>``) with component-less
   BOM uploads, then upload the image BOM under ``build/<repo>/<image>``,
4. with ``--fail-on-severity``: poll the event token until DT finished processing,
   fetch the findings and fail on any unsuppressed one at or above the floor,
5. write a findings summary to ``$GITHUB_STEP_SUMMARY`` and results to ``$GITHUB_OUTPUT``.

Failure policy: a Dependency-Track (or syft) failure never fails the build unless a
severity floor is set; then it fails closed. Invalid inputs always fail.
The API key is read from ``$DTRACK_API_KEY`` only and is never printed.

Exit codes: 0 ok / non-fatal problem, 1 gate failed or fail-closed, 2 invalid input.
"""

import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

API_KEY_ENV = "DTRACK_API_KEY"
DEFAULT_URL = "http://dependency-track-api-server.dependency-track.svc.cluster.local:8080"
CYCLONEDX_SPEC = "1.5"
# Parents are looked up by name *and* version, so they all use one fixed version.
PARENT_VERSION = "latest"
ROOT_PARENT = "build"
DEFAULT_TAG = "build"

# Pinned syft. Bump the version and both digests together (sha256 of the release tarballs,
# from syft_<version>_checksums.txt).
SYFT_VERSION = "1.56.0"
SYFT_SHA256 = {
    "amd64": "1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528",
    "arm64": "ace61b9397ae28189c674ae332d67a8074dafd71e87724dfb8b22412d8253bb5",
}
SYFT_BASE_URL = "https://github.com/anchore/syft/releases/download"

SEVERITY_RANK = {"UNASSIGNED": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
GATE_FLOORS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
BULKY_PROPERTY_PREFIXES = ("syft:location", "syft:metadata", "syft:file")
IMAGE_SCHEMES = ("docker", "podman", "containerd", "registry", "docker-archive",
                 "oci-archive", "oci-dir", "singularity", "dir", "file")
SUMMARY_ROWS = 50
# DT column limits (Component table): one over-long value makes the whole BOM import fail
# terminally ("value ... in column PURLCOORDINATES that has maximum length of 1024").
MAX_PURL = 1024
MAX_FIELD = 255


class ConfigError(Exception):
    """Invalid input: always fails the step."""


class SoftError(Exception):
    """Syft/DT problem: fails the step only when a severity floor is set."""


def log(message):
    print("sbom-dependency-track: %s" % message, flush=True)


def annotate(level, message):
    """GitHub workflow-command annotation (data escaped as the runner expects)."""
    data = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::%s title=SBOM -> Dependency-Track::%s" % (level, data), flush=True)


# ── Inputs ───────────────────────────────────────────────────────────────────


def split_image(ref):
    """Return (repository path without registry tag/digest, tag or '', digest or '')."""
    for scheme in IMAGE_SCHEMES:
        if ref.startswith(scheme + ":") and not ref.startswith(scheme + "://"):
            ref = ref[len(scheme) + 1:]
            break
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = ""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
        ref = ref[:len(ref) - len(tag) - 1]
    return ref, tag, digest


def image_basename(ref):
    path, _, _ = split_image(ref)
    name = path.rstrip("/").rsplit("/", 1)[-1]
    if not name or name in (".", ".."):
        raise ConfigError("cannot derive an image name from %r; pass `project` explicitly" % ref)
    return name


def parse_seconds(value, name, minimum_exclusive=None):
    """'120' or '120s' -> 120.0; finite, >= 0 (or > minimum_exclusive)."""
    try:
        seconds = float(str(value).strip().rstrip("sS"))
    except (TypeError, ValueError):
        raise ConfigError("%s must be a number of seconds, got %r" % (name, value)) from None
    if not seconds >= 0 or seconds == float("inf") or (minimum_exclusive is not None and seconds <= minimum_exclusive):
        raise ConfigError("%s must be a finite number of seconds%s, got %r" % (
            name, " greater than 0" if minimum_exclusive is not None else " >= 0", value))
    return seconds


def resolve_settings(args, environ):
    image = (args.image or "").strip()
    if not image:
        raise ConfigError("`image` is required")
    floor = (args.fail_on_severity or "").strip().upper()
    if floor and floor not in GATE_FLOORS:
        raise ConfigError("fail-on-severity must be one of %s (or empty), got %r" % (
            ", ".join(GATE_FLOORS), args.fail_on_severity))
    wait_timeout = parse_seconds(args.wait_timeout, "wait-timeout", minimum_exclusive=0)
    import_wait = parse_seconds(args.import_wait, "import-wait")

    repo_full = (args.repo or environ.get("GITHUB_REPOSITORY") or "").strip()
    repo = repo_full.rsplit("/", 1)[-1]
    project = (args.project or "").strip()
    parent = (args.parent or "").strip()
    if not project or not parent:
        if not repo:
            raise ConfigError("GITHUB_REPOSITORY (or --repo) is needed to derive the default project/parent; "
                              "pass `project` and `parent` explicitly")
    if not project:
        project = "%s/%s/%s" % (ROOT_PARENT, repo, image_basename(image))
    if not parent:
        parent = "%s/%s" % (ROOT_PARENT, repo)

    _, tag, _ = split_image(image)
    version = (args.version or "").strip() or tag
    if not version:
        sha = (args.git_sha or environ.get("GITHUB_SHA") or "").strip()
        if not sha:
            raise ConfigError("the image has no tag and no GITHUB_SHA is set; pass `version` explicitly")
        version = sha[:7]

    url = (args.url or DEFAULT_URL).strip().rstrip("/")
    if not re.match(r"^https?://", url):
        raise ConfigError("dtrack-url must start with http:// or https://, got %r" % url)

    return {
        "image": image,
        "project": project,
        "version": version,
        "parent": parent,
        "tags": [t for t in (args.tag or [DEFAULT_TAG]) if t],
        "url": url,
        "floor": floor,
        "wait_timeout": wait_timeout,
        "import_wait": import_wait,
        "sbom_out": args.sbom_out,
        "syft": args.syft,
        "syft_dir": args.syft_dir,
        "poll_interval": args.poll_interval,
        "parent_wait": args.parent_wait,
        "retry_delay": args.retry_delay,
        "attempts": max(1, args.upload_attempts),
    }


# ── Syft ─────────────────────────────────────────────────────────────────────


def syft_arch(machine=None):
    machine = (machine or platform.machine()).lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise SoftError("unsupported CPU architecture %r for syft (amd64/arm64 only)" % machine)


def install_syft(dest_dir, version=SYFT_VERSION, checksums=None, base_url=SYFT_BASE_URL, arch=None):
    """Download syft, verify its sha256 against the pinned table, return the binary path."""
    checksums = SYFT_SHA256 if checksums is None else checksums
    arch = arch or syft_arch()
    target = os.path.join(dest_dir, "syft-%s-%s" % (version, arch))
    if os.access(target, os.X_OK):
        return target
    expected = checksums.get(arch)
    if not expected:
        raise SoftError("no pinned sha256 for syft %s %s" % (version, arch))
    url = "%s/v%s/syft_%s_linux_%s.tar.gz" % (base_url.rstrip("/"), version, version, arch)
    log("downloading syft %s (%s)" % (version, arch))
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            blob = response.read()
    except (urllib.error.URLError, OSError) as error:
        raise SoftError("cannot download syft from %s: %s" % (url, getattr(error, "reason", error))) from None
    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise SoftError("syft tarball checksum mismatch: expected %s, got %s" % (expected, actual))
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            member = archive.getmember("syft")
            data = archive.extractfile(member).read()
    except (tarfile.TarError, KeyError, AttributeError, OSError) as error:
        raise SoftError("cannot extract syft from the tarball: %s" % error) from None
    os.makedirs(dest_dir, exist_ok=True)
    partial = target + ".partial"
    with open(partial, "wb") as handle:
        handle.write(data)
    os.chmod(partial, 0o755)
    os.replace(partial, target)
    return target


def syft_target(image):
    """A digest-pinned ref is a pushed image: scan exactly that manifest from the registry."""
    if any(image.startswith(s + ":") for s in IMAGE_SCHEMES):
        return image
    if "@sha256:" in image:
        return "registry:" + image
    return image


def run_syft(syft, image, out_path):
    env = dict(os.environ, SYFT_FILE_METADATA_SELECTION="none", SYFT_CHECK_FOR_APP_UPDATE="false")
    command = [syft, syft_target(image), "-q", "-o", "cyclonedx-json=%s" % out_path]
    log("running syft on %s" % image)
    try:
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SoftError("syft could not run: %s" % error) from None
    if result.returncode != 0:
        raise SoftError("syft failed (exit %d): %s" % (result.returncode, result.stderr.strip()[-800:]))
    try:
        with open(out_path, encoding="utf-8") as handle:
            bom = json.load(handle)
    except (OSError, ValueError) as error:
        raise SoftError("syft produced no readable BOM: %s" % error) from None
    if bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("components", []), list):
        raise SoftError("syft output is not a CycloneDX BOM")
    return bom


def component_identity(component):
    return component.get("purl") or (
        component.get("type"), component.get("group"), component.get("name"), component.get("version"))


CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def purl_is_garbage(purl):
    """Control characters, truncated %-escapes, or escapes that do not decode to UTF-8 (e.g. %FFFFFFC3)."""
    if CONTROL_CHARS.search(purl) or BAD_PERCENT_ESCAPE.search(purl):
        return True
    try:
        urllib.parse.unquote_to_bytes(purl).decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


# Bytes DT's packageurl re-encoding leaves alone; any other ASCII byte becomes %XX (3 chars).
PURL_PLAIN_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_~:/")


def projected_purl_length(purl):
    """Length DT will store: it re-canonicalises the purl and writes every non-ASCII UTF-8 byte as a
    sign-extended %FFFFFFxx (9 chars), so a short mojibake name can overflow the 1024-char PURLCOORDINATES
    column. ASCII counts 1 (3 when it needs escaping); percent-escapes are decoded first."""
    total = 0
    for byte in urllib.parse.unquote_to_bytes(purl):
        total += 9 if byte >= 0x80 else 1 if byte in PURL_PLAIN_BYTES else 3
    return total


def exceeds_dt_limits(component):
    """True if DT cannot store the component (garbage names from binary scanning, e.g. mojibake nuget ids)."""
    purl = str(component.get("purl") or "")
    if len(purl) > MAX_PURL or purl_is_garbage(purl) or projected_purl_length(purl) > MAX_PURL:
        return True
    for key in ("name", "version", "group"):
        value = str(component.get(key) or "")
        if len(value) > MAX_FIELD or CONTROL_CHARS.search(value):
            return True
    return False


def slim_bom(bom):
    """Drop `file` components, evidence, bulky syft properties, duplicates and components DT cannot store."""
    components = bom.get("components") or []
    kept, seen, refs, oversized = [], set(), set(), []
    for component in components:
        if component.get("type") == "file":
            continue
        if exceeds_dt_limits(component):
            oversized.append(component)
            continue
        identity = component_identity(component)
        if identity in seen:
            continue
        seen.add(identity)
        component = {k: v for k, v in component.items() if k != "evidence"}
        properties = [p for p in component.get("properties") or []
                      if not str(p.get("name", "")).startswith(BULKY_PROPERTY_PREFIXES)]
        if properties:
            component["properties"] = properties
        else:
            component.pop("properties", None)
        if component.get("bom-ref"):
            refs.add(component["bom-ref"])
        kept.append(component)
    bom["components"] = kept
    root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if root:
        refs.add(root)
    if "dependencies" in bom:
        bom["dependencies"] = [
            dict(entry, dependsOn=[r for r in entry.get("dependsOn") or [] if r in refs])
            for entry in bom.get("dependencies") or [] if entry.get("ref") in refs]
    log("slimmed BOM: %d -> %d component(s)" % (len(components), len(kept)))
    if oversized:
        example = str(oversized[0].get("purl") or oversized[0].get("name") or "")[:120]
        annotate("warning", "dropped %d component(s) DT cannot store (over-long or malformed purl/name/version; "
                 "one would fail the whole import), e.g. %r" % (len(oversized), example))
    return bom


def empty_bom(name, version):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "bom-ref": "group:" + name, "name": name, "version": version},
        },
        "components": [],
    }


# ── Dependency-Track client ──────────────────────────────────────────────────


class DTrack:
    def __init__(self, url, api_key, attempts=3, retry_delay=5.0, timeout=60):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.attempts = attempts
        self.retry_delay = retry_delay
        self.timeout = timeout

    def _scrub(self, text):
        return str(text).replace(self.api_key, "***") if self.api_key else str(text)

    def request(self, method, path, body=None, query=None, retry=True):
        """Return (status, headers, parsed JSON). Retries 5xx/429/network errors; 4xx raises at once."""
        url = self.url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        attempts = self.attempts if retry else 1
        message = ""
        for attempt in range(1, attempts + 1):
            headers = {"X-Api-Key": self.api_key, "Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    raw = response.read()
                    payload = json.loads(raw) if raw.strip() else None
                    return response.status, response.headers, payload
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", "replace").strip()[:300]
                message = "HTTP %d from %s %s: %s" % (error.code, method, path, detail)
                if error.code < 500 and error.code != 429:
                    if error.code in (401, 403):
                        message += " (is the API key valid, with BOM_UPLOAD, PROJECT_CREATION_UPLOAD and VIEW_VULNERABILITY?)"
                    raise SoftError(self._scrub(message)) from None
            except ValueError as error:
                raise SoftError(self._scrub("invalid JSON from %s %s: %s" % (method, path, error))) from None
            except (urllib.error.URLError, OSError) as error:
                message = "cannot reach %s: %s" % (self.url, getattr(error, "reason", error))
            if attempt < attempts:
                log(self._scrub("%s; retrying in %gs (attempt %d of %d)" % (
                    message, self.retry_delay, attempt, attempts)))
                time.sleep(self.retry_delay)
        raise SoftError(self._scrub(message))

    def upload(self, name, version, bom, tags=(), parent=None, parent_version=PARENT_VERSION):
        document = json.dumps(bom, separators=(",", ":")).encode("utf-8")
        body = {
            "projectName": name,
            "projectVersion": version,
            "autoCreate": True,
            "bom": base64.b64encode(document).decode("ascii"),
        }
        if tags:
            body["projectTags"] = [{"name": t} for t in tags]
        if parent:
            body["parentName"] = parent
            body["parentVersion"] = parent_version
        _, _, payload = self.request("PUT", "/api/v1/bom", body=body)
        token = (payload or {}).get("token")
        if not token:
            raise SoftError("DT accepted the upload of %s but returned no token" % name)
        log("uploaded %s/%s (%d bytes of BOM)" % (name, version, len(document)))
        return token

    def is_processing(self, token):
        _, _, payload = self.request("GET", "/api/v1/event/token/%s" % urllib.parse.quote(token, safe=""))
        return bool((payload or {}).get("processing"))

    def wait(self, token, timeout, interval):
        deadline = time.monotonic() + timeout
        while True:
            try:
                if not self.is_processing(token):
                    return
            except SoftError as error:
                if time.monotonic() >= deadline:
                    raise
                log("token poll failed (%s); retrying" % error)
            if time.monotonic() >= deadline:
                raise SoftError("DT was still processing the BOM after %gs" % timeout)
            time.sleep(interval)

    def project(self, name, version):
        _, _, payload = self.request("GET", "/api/v1/project/lookup", query={"name": name, "version": version})
        if not (payload or {}).get("uuid"):
            raise SoftError("project %s/%s not found in DT after upload" % (name, version))
        return payload

    def component_count(self, project_uuid):
        _, headers, payload = self.request("GET", "/api/v1/component/project/%s" % project_uuid,
                                           query={"pageSize": 1, "pageNumber": 1})
        try:
            return int(headers.get("X-Total-Count"))
        except (TypeError, ValueError):
            return len(payload or [])

    def findings(self, project_uuid, page_size=100):
        found, page = [], 1
        while True:
            _, headers, payload = self.request(
                "GET", "/api/v1/finding/project/%s" % project_uuid,
                query={"pageNumber": page, "pageSize": page_size, "suppressed": "false"})
            payload = payload or []
            found.extend(payload)
            try:
                total = int(headers.get("X-Total-Count", len(found)))
            except (TypeError, ValueError):
                total = len(found)
            if not payload or len(found) >= total:
                return found
            page += 1


def project_chain(path):
    """'build/repo' -> ['build', 'build/repo'], each entry parented by the previous."""
    parts = [p for p in path.split("/") if p]
    return ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]


def ensure_parents(client, parent, wait_each=10.0, interval=1.0):
    """Create grouping projects top-down with component-less uploads (idempotent)."""
    previous = None
    for name in project_chain(parent):
        token = client.upload(name, PARENT_VERSION, empty_bom(name, PARENT_VERSION), parent=previous)
        # DT sets a parent only when it creates the project; make sure the parent has been
        # created before anything is attached to it. Best effort: the project record exists
        # as soon as the upload is accepted.
        try:
            client.wait(token, wait_each, interval)
        except SoftError as error:
            log("could not confirm parent %s was processed: %s" % (name, error))
        previous = name


# ── Findings / gate ──────────────────────────────────────────────────────────


def severity_of(finding):
    return str((finding.get("vulnerability") or {}).get("severity") or "UNASSIGNED").upper()


def active_findings(findings):
    return [f for f in findings if not (f.get("analysis") or {}).get("isSuppressed")]


def blocking_findings(findings, floor):
    if not floor:
        return []
    threshold = SEVERITY_RANK[floor]
    return [f for f in active_findings(findings) if SEVERITY_RANK.get(severity_of(f), 0) >= threshold]


def finding_sort_key(finding):
    vuln = finding.get("vulnerability") or {}
    return (-SEVERITY_RANK.get(severity_of(finding), 0), -(vuln.get("epssScore") or 0), str(vuln.get("vulnId")))


def md_cell(value):
    return str(value if value not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def render_summary(settings, status, findings=None):
    lines = ["### SBOM -> Dependency-Track", "",
             "| | |", "|---|---|",
             "| Image | `%s` |" % md_cell(settings["image"]),
             "| Project | `%s` @ `%s` |" % (md_cell(settings["project"]), md_cell(settings["version"])),
             "| Status | %s |" % md_cell(status)]
    if settings["floor"]:
        lines.append("| Gate | fail on `%s` or higher |" % settings["floor"])
    if findings is not None:
        active = sorted(active_findings(findings), key=finding_sort_key)
        counts = {}
        for finding in active:
            counts[severity_of(finding)] = counts.get(severity_of(finding), 0) + 1
        lines += ["", "| Severity | Findings |", "|---|---|"]
        for severity in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True):
            lines.append("| %s | %d |" % (severity, counts.get(severity, 0)))
        if active:
            lines += ["", "| Severity | Vulnerability | Component | Version | EPSS |", "|---|---|---|---|---|"]
            for finding in active[:SUMMARY_ROWS]:
                vuln, comp = finding.get("vulnerability") or {}, finding.get("component") or {}
                epss = vuln.get("epssScore")
                lines.append("| %s | %s | %s | %s | %s |" % (
                    severity_of(finding), md_cell(vuln.get("vulnId")), md_cell(comp.get("name")),
                    md_cell(comp.get("version")), "%.3f" % epss if isinstance(epss, (int, float)) else "-"))
            if len(active) > SUMMARY_ROWS:
                lines.append("")
                lines.append("_%d more finding(s) not shown._" % (len(active) - SUMMARY_ROWS))
    return "\n".join(lines) + "\n"


def append_file(env_name, text):
    path = os.environ.get(env_name)
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def set_outputs(**values):
    append_file("GITHUB_OUTPUT", "".join("%s=%s\n" % (k.replace("_", "-"), v) for k, v in values.items()))


# ── Entry point ──────────────────────────────────────────────────────────────


class ImportFailed(SoftError):
    """DT accepted the upload but did not import the BOM."""


def verify_import(client, project, expected_components):
    """The project must have a BOM import and, if the BOM had components, a non-zero component count."""
    if not project.get("lastBomImport"):
        raise ImportFailed("DT did not import the BOM: project %s/%s has no BOM import (lastBomImport is null); "
                           "check the DT API server log for the ImportBomActivity error" % (
                               project.get("name"), project.get("version")))
    if expected_components:
        count = client.component_count(project["uuid"])
        if count == 0:
            raise ImportFailed("DT did not import the BOM: project %s/%s has 0 components but the SBOM had %d; "
                               "check the DT API server log for the ImportBomActivity error" % (
                                   project.get("name"), project.get("version"), expected_components))


def execute(settings, api_key, outputs):
    """Run the pipeline. Fills `outputs`; returns (status, findings, blocking, warning)."""
    syft = settings["syft"]
    if not syft:
        syft_dir = settings["syft_dir"] or os.path.join(
            os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), "sbom-dependency-track-bin")
        syft = install_syft(syft_dir)
    out_path = settings["sbom_out"]
    bom = run_syft(syft, settings["image"], out_path)
    slim_bom(bom)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(bom, handle, separators=(",", ":"))
    outputs["sbom_path"] = out_path
    path, _, digest = split_image(settings["image"])
    if digest and not any(settings["image"].startswith(s + ":") for s in IMAGE_SCHEMES):
        outputs["image_digest_ref"] = "%s@%s" % (path, digest)

    client = DTrack(settings["url"], api_key, settings["attempts"], settings["retry_delay"])
    ensure_parents(client, settings["parent"], wait_each=settings["parent_wait"], interval=settings["poll_interval"])
    token = client.upload(settings["project"], settings["version"], bom, tags=settings["tags"],
                          parent=settings["parent"])
    outputs["token"] = token
    floor = settings["floor"]

    # Verify the import in every mode: DT accepts the upload and fails the import later, silently.
    try:
        client.wait(token, settings["wait_timeout"] if floor else settings["import_wait"], settings["poll_interval"])
        project = client.project(settings["project"], settings["version"])
        outputs["project_uuid"] = project["uuid"]
        verify_import(client, project, len(bom["components"]))
        outputs["imported"] = "true"
    except ImportFailed as error:
        outputs["imported"] = "false"
        if floor:
            raise
        return "uploaded, NOT imported (token %s)" % token, None, [], str(error)
    except SoftError as error:
        outputs["imported"] = "unknown"
        if floor:
            raise
        return "uploaded (token %s); import not confirmed" % token, None, [], "could not confirm DT imported the BOM: %s" % error

    if not floor:
        return "uploaded and imported (token %s); no vulnerability gate" % token, None, [], ""

    findings = client.findings(project["uuid"])
    blocking = blocking_findings(findings, floor)
    return "processed", findings, blocking, ""


def run(args, environ=None):
    environ = os.environ if environ is None else environ
    api_key = environ.get(API_KEY_ENV, "").strip()
    try:
        settings = resolve_settings(args, environ)
    except ConfigError as error:
        log("invalid input: %s" % error)
        return 2

    outputs = {"project": settings["project"], "version": settings["version"], "gate": "skipped"}
    floor = settings["floor"]
    findings, blocking = None, []

    def finish(rc, status, gate, level=None, message=""):
        outputs["gate"] = gate
        if "token" in outputs:
            outputs.setdefault("imported", "unknown")
        outputs.setdefault("imported", "false")
        if message:
            annotate(level, message)
            log(message)
        append_file("GITHUB_STEP_SUMMARY", render_summary(settings, status, findings))
        outputs["findings_total"] = len(active_findings(findings)) if findings is not None else ""
        outputs["findings_blocking"] = len(blocking) if findings is not None else ""
        set_outputs(**outputs)
        return rc

    if not api_key:
        message = "no %s provided (fork PR without secrets?); nothing uploaded" % API_KEY_ENV
        if floor:
            return finish(1, "not uploaded: no API key", "unavailable", "error",
                          message + "; failing because fail-on-severity=%s" % floor)
        return finish(0, "skipped: no API key", "skipped", "warning", message)

    try:
        status, findings, blocking, warning = execute(settings, api_key, outputs)
    except SoftError as error:
        message = str(error)
        if floor:
            return finish(1, "FAILED: %s" % message, "unavailable", "error",
                          "%s; failing closed because fail-on-severity=%s" % (message, floor))
        return finish(0, "not uploaded: %s" % message, "skipped", "warning",
                      "%s; the build is not affected (no fail-on-severity set)" % message)

    if not floor:
        return finish(0, status, "skipped", "warning" if warning else None, warning)
    if blocking:
        worst = ", ".join("%s (%s)" % ((f.get("vulnerability") or {}).get("vulnId"), severity_of(f))
                          for f in sorted(blocking, key=finding_sort_key)[:5])
        return finish(1, "gate FAILED: %d finding(s) at %s or higher" % (len(blocking), floor), "failed", "error",
                      "%d unsuppressed finding(s) at %s or higher in %s/%s, e.g. %s" % (
                          len(blocking), floor, settings["project"], settings["version"], worst))
    return finish(0, "gate passed: no unsuppressed finding at %s or higher" % floor, "passed")


def build_parser():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="generate the SBOM, upload it and optionally gate")
    r.add_argument("--image", required=True)
    r.add_argument("--project", default="")
    r.add_argument("--version", default="")
    r.add_argument("--parent", default=None, help="grouping parent path; default build/<repo>")
    r.add_argument("--repo", default="", help="owner/name or name; default $GITHUB_REPOSITORY")
    r.add_argument("--git-sha", default="")
    r.add_argument("--url", default=DEFAULT_URL)
    r.add_argument("--tag", action="append", help="project tag (repeatable; default: build)")
    r.add_argument("--fail-on-severity", default="")
    r.add_argument("--wait-timeout", default="300")
    r.add_argument("--import-wait", default="120",
                   help="report-only mode: seconds to wait for DT to import the BOM before checking (gate mode "
                        "uses --wait-timeout)")
    r.add_argument("--sbom-out", default="sbom.cdx.json")
    r.add_argument("--syft", default="", help="use this syft instead of the pinned download")
    r.add_argument("--syft-dir", default="", help="where to cache the downloaded syft")
    r.add_argument("--poll-interval", type=float, default=5.0)
    r.add_argument("--parent-wait", type=float, default=10.0,
                   help="seconds to wait for each grouping parent to be processed (best effort)")
    r.add_argument("--retry-delay", type=float, default=5.0)
    r.add_argument("--upload-attempts", type=int, default=3)
    return p


def main(argv=None):
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return run(args)
    except Exception as error:  # noqa: BLE001 -- never leak a traceback with request details
        key = os.environ.get(API_KEY_ENV, "").strip()
        detail = str(error).replace(key, "***") if key else str(error)
        log("FAILED: unexpected %s: %s" % (type(error).__name__, detail))
        return 1 if (args.fail_on_severity or "").strip() else 0


if __name__ == "__main__":
    sys.exit(main())
