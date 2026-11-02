# pipeline-templates

Shared GitHub Actions for FactusConsulting repos: reusable workflows and composite actions.

Currently: **SBOM -> Dependency-Track** for every container build. After an image is built, a
CycloneDX SBOM is generated with [syft](https://github.com/anchore/syft), uploaded to
Dependency-Track (DT) and, optionally, used as a vulnerability gate and attested to the image
with cosign.

Portfolio layout in DT: hosts under `hosts`, Kubernetes workloads under `k8s` -> `k8s/<namespace>`,
CI builds under `build` -> `build/<repo>`. A build is the project `build/<repo>/<image-name>`,
version = image tag (else short git sha), tag `build`. The grouping parents are created on first use.

## Versioning

Consumers pin the moving major tag: **`@v1`**. Releases are tagged `vX.Y.Z` (immutable), and the
`v1` tag is moved to the newest `v1.x.y` release (`git tag -f v1 vX.Y.Z && git push -f origin v1`).
Breaking input/behaviour changes get a new major (`v2`). The reusable workflow itself calls the
composite action at `@v1`, so both always move together.

## Use it

### 1. Composite action: a step right after the image is pushed (recommended)

```yaml
jobs:
  build:
    runs-on: arc-runner
    permissions:
      contents: read
      packages: write
      id-token: write          # only with attest: true
    steps:
      - uses: actions/checkout@<sha> # vX
      - uses: docker/login-action@<sha> # vX
        with: { registry: ghcr.io, username: "${{ github.actor }}", password: "${{ secrets.GITHUB_TOKEN }}" }
      - id: build
        uses: docker/build-push-action@<sha> # vX
        with:
          push: true
          tags: ghcr.io/factusconsulting/my-app:${{ github.sha }}
      - uses: FactusConsulting/pipeline-templates/sbom-dependency-track@v1
        with:
          image: ghcr.io/factusconsulting/my-app:${{ github.sha }}@${{ steps.build.outputs.digest }}
          dtrack-api-key: ${{ secrets.DTRACK_API_KEY }}
          # fail-on-severity: HIGH     # optional gate
          # attest: true               # optional cosign attestation
```

The runner's docker credentials (from the login step) are used by syft and cosign. A local image
(not pushed, e.g. `my-app:dev` in the runner's docker daemon) works too, without digest.

### 2. Reusable workflow: a separate job

```yaml
jobs:
  build:
    # ... builds and pushes; expose the ref as a job output ...
  sbom:
    needs: build
    permissions:
      contents: read
      packages: read           # ghcr login with the caller's GITHUB_TOKEN
      id-token: write          # only with attest: true
    uses: FactusConsulting/pipeline-templates/.github/workflows/sbom-dependency-track.yaml@v1
    with:
      image: ghcr.io/factusconsulting/my-app:${{ github.sha }}@${{ needs.build.outputs.digest }}
      runs-on: '["self-hosted","arc-runner-hotlaps"]'   # default '"arc-runner"'
      fail-on-severity: HIGH
    secrets:
      DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
```

`runs-on` is a JSON string (a label or an array of labels). The caller must grant the job
`id-token: write` only when `attest: true`.

## Inputs

| Input (action and workflow) | Default | Meaning |
|---|---|---|
| `image` (required) | | Image ref, ideally `repo:tag@sha256:...`. With a digest, syft scans exactly that pushed manifest from the registry (for a multi-arch index: the runner's architecture). Without: syft's usual resolution (local docker daemon first, then registry). |
| `project` | `build/<repo-name>/<image basename>` | DT project name. |
| `version` | image tag, else short git sha | DT project version. |
| `dtrack-url` | `http://dependency-track-api-server.dependency-track.svc.cluster.local:8080` | DT API base URL (see network note). |
| `dtrack-api-key` (action, required) / secret `DTRACK_API_KEY` (workflow) | | DT API key. Masked, never printed. Permissions: `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`; `VIEW_VULNERABILITY` and `VIEW_PORTFOLIO` for the gate. |
| `parent` | `build/<repo-name>` | Grouping parent; every path prefix is created top-down (`build`, `build/<repo>`). |
| `fail-on-severity` | empty = report only | `CRITICAL`, `HIGH`, `MEDIUM` or `LOW`: fail on any unsuppressed finding at or above it. |
| `wait-timeout` | `300` | Seconds to wait for DT to finish processing before the gate gives up (gate only). |
| `import-wait` | `120` | Report-only mode: seconds to wait for DT to import the BOM before verifying the import (gate mode uses `wait-timeout`). |
| `attest` | `false` | `true`: `cosign attest --type cyclonedx` the SBOM to the image (keyless, GitHub OIDC). Needs `id-token: write` and an image ref with `@sha256` digest. |
| `registry` (workflow only) | `ghcr.io` | Registry to log in to with the caller's `GITHUB_TOKEN` (`packages: read`). Empty = no login. |
| `runs-on` (workflow only) | `'"arc-runner"'` | JSON for `runs-on`. |

| Output | Meaning |
|---|---|
| `project`, `version` | DT project name and version used. |
| `sbom-path` | The slimmed CycloneDX file (empty if generation failed). |
| `imported` | `true`: DT imported the BOM. `false`: DT did not import it (or nothing was uploaded). `unknown`: DT could not be queried, or was still processing when `import-wait` ran out. |
| `gate` | `passed` / `failed` / `unavailable` (gate could not be evaluated) / `skipped` (no `fail-on-severity`). |
| `project-uuid` | DT project uuid, once looked up after the upload. |
| `findings-total`, `findings-blocking` | Unsuppressed findings / those at or above the floor (gate mode only). |

## Behaviour

1. Installs a pinned syft (version and sha256 in `dtrack.py`, linux amd64/arm64, checksum-verified) and runs
   `syft <image> -o cyclonedx-json`. `file` components, per-file evidence and duplicates are dropped, as in the host uploader. Components DT cannot
   store are dropped too (purl over 1024 characters, name/version/group over 255, control characters, or a purl
   with invalid %-escapes such as `%FFFFFFC3`) with a `dropped N component(s) DT cannot store` warning: one such
   component makes DT fail the whole import.
2. Creates the parents `build` and `build/<repo>` with component-less BOM uploads (idempotent; DT only
   applies a parent when it creates a project), then uploads the BOM (`PUT /api/v1/bom`, `autoCreate`).
3. Verifies the import in **every** mode: polls `/api/v1/event/token/<token>` (up to `import-wait`, or
   `wait-timeout` with a gate), looks the project up and checks that `lastBomImport` is set and, if the SBOM had
   components, that the project has more than 0 components. DT accepts a BOM and imports it asynchronously, so a
   bad BOM otherwise fails silently. A failed import is a `::warning` and `imported=false` (report-only) or an
   `::error` and a failed step (gate mode). With `fail-on-severity`, it then reads
   `/api/v1/finding/project/<uuid>` and fails on any unsuppressed finding at or above the floor. Report-only mode
   therefore waits up to `import-wait` (default 120 s) for DT, normally a few seconds.
4. Writes a severity count table and the findings list (worst first, EPSS) to the job summary.
5. `attest: true`: installs cosign and attests the SBOM to `image@digest`.

Failure policy: **report-only never breaks a build.** A DT outage (also during the import check), failed
import, bad API key, syft failure or missing python3 (the action installs it with `actions/setup-python` when absent) is a `::warning` and the step
succeeds. With `fail-on-severity` set it fails closed with a clear message (the SBOM is still attested first,
if requested). Invalid inputs always fail. A missing API key (e.g. fork PRs) skips the upload the same way.

## Network note: DT is reached in-cluster

All container builds run on ARC runners inside the homek8s cluster, and some runner profiles are
`restricted` (egress to `192.168.0.0/16` is blocked). `dtrack.lwa.dk` resolves to a LAN address, so CI **must use
the in-cluster URL** (the default). Restricted runners additionally need a NetworkPolicy allowing egress from the
`arc-runners` namespace to the `dependency-track` namespace, `dependency-track-api-server` on TCP 8080. Runners also need
to reach `github.com` (syft download, cosign installer) and, for attestation, the Sigstore services
(`fulcio.sigstore.dev`, `rekor.sigstore.dev`).

## Development

```
python3 -m pytest -q tests          # unit + end-to-end tests against a stub DT server
actionlint                          # workflows
python3 scripts/action_as_workflow.py sbom-dependency-track/action.yml > /tmp/a.yaml && actionlint /tmp/a.yaml
```

`sbom-dependency-track/dtrack.py` is stdlib-only (Python 3.8+) and holds all logic; the YAML stays thin.
Bumping syft: change `SYFT_VERSION` and both `SYFT_SHA256` entries together. Third-party actions are pinned by
commit SHA; Dependabot (`.github/dependabot.yml`) proposes updates. CI (`.github/workflows/ci.yaml`) runs
actionlint (pinned, checksum-verified) and pytest on every PR.
