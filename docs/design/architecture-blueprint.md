# Architecture Blueprint: Hexagonal core, workspace packages, decoupled repos

> Status: **design / RFC** — proposal for review, no code yet. Companion to
> [zero-trust-rbac.md](zero-trust-rbac.md). This document describes a target
> structure and a **phased, non-breaking** path to it. Nothing here is committed
> until the phase it belongs to is approved.

## 1. Executive summary & operational context

Kaaval runs the **same risk engine** in two very different homes: a
zero-dependency CLI (`python -m app.cli scan rbac …`, no server, no database)
and a stateful FastAPI + Postgres web service. Today both live in one flat
package, `control-plane/app/`, where pure scoring logic sits beside SQLAlchemy
models, a Kubernetes client, JWT auth, and a PDF renderer.

That already works — but the boundary is *implicit*. The goal of this blueprint
is to make it **explicit**, so the domain (the "does this finding matter, and
how much" logic) has **zero dependency on web, database, or cluster I/O**. That
single rule — the domain imports no infrastructure — is what "eliminating
runtime pollution" means here.

Why it's worth doing:

- **The engine must behave identically in both hosts.** A pure core with no
  ambient state guarantees the CLI and the web service score a finding the same
  way, forever, and it's testable with plain fixtures (which is already how
  `tests/test_rbac_service.py` and `tests/test_cli.py` work).
- **The planned Go engine** (`cloud-scanner/`, ROADMAP "further out") re-uses the
  *contract*, not the Python. A clean port boundary is what makes a second
  implementation possible without forking semantics.
- **CNCF-standard layout.** Graduated K8s-ecosystem projects ship the operator/
  CLI, the Helm chart, and the GitHub Action as **separate versioned artifacts**.
  Adopting that now costs little and reads as maturity on the Sandbox track.

**Honest framing (read this before Section 8).** The pure core *already exists*
as functions — this is refactoring toward an explicit shape, not a rewrite. The
ROI is real, but a big-bang restructure mid-Sandbox-push, with three active
contributors mid-PR, would be reckless. So the roadmap (§8) is **phased so the
high-value, zero-disruption pieces land first** and the heavy moves are gated on
real need. This RFC is a map, not a mandate to do all of it at once.

## 2. Target GitHub organization model

Three concerns that version and release on **different clocks** become three
repos under the `kaaval` org:

| Repo | Contents | Why separate |
|---|---|---|
| **`kaaval/kaaval`** | the scanner: core + CLI + web + dashboard | the product |
| **`kaaval/helm-charts`** | the Helm chart ([#8](https://github.com/kaaval/kaaval/issues/8)) | charts version independently of app images; standard `helm repo` / Artifact Hub publishing wants its own tag stream + `gh-pages` index |
| **`kaaval/github-action`** | the composite scan Action (today `.github/actions/kaaval-scan/`) | Marketplace ([#34](https://github.com/kaaval/kaaval/issues/34)) publishes from a repo root with its own `v1`/`v2` release tags; users pin `kaaval/github-action@v1`, decoupled from the scanner's version |

This is the conventional split (compare `prometheus-community/helm-charts`,
`aquasecurity/trivy-action`). It's a **Phase 1 / Phase 3** move, not day-one —
see §8. The main repo keeps working throughout: the Action can live in-repo until
Marketplace publication actually needs the standalone repo.

## 3. Decoupled folder topology

The target separates **pure packages** from **runtime hosts**:

```
kaaval/                          (repo)
├── packages/
│   └── kaaval-core/             pure domain — NO fastapi/sqlalchemy/kubernetes
│       ├── pyproject.toml
│       └── kaaval_core/
│           ├── models.py        Finding, RiskContext, Score (pydantic)
│           ├── scoring.py       compute_contextual_score()      ← from app/scoring.py
│           ├── remediation.py   build_remediation()             ← from app/remediation.py
│           ├── rbac/
│           │   └── rules.py     evaluate_rbac_findings() + predicates ← app/rbac_service.py (pure parts)
│           ├── cve/
│           │   └── matching.py  CVE↔version matching            ← app/cve_service.py (pure parts)
│           └── ports.py         abstract interfaces (§4)
├── apps/
│   ├── kaaval-cli/              host — kaaval-core + kubernetes client, NO web/db
│   │   ├── pyproject.toml
│   │   └── kaaval_cli/
│   │       ├── main.py          argparse + gating          ← app/cli.py
│   │       └── manifest_source.py  build_graph_from_manifests()  ← app/cli.py (adapter)
│   └── kaaval-web/              host — kaaval-core + fastapi + sqlalchemy + …
│       ├── pyproject.toml
│       └── kaaval_web/
│           ├── main.py          FastAPI wiring             ← app/main.py
│           ├── routers/         cve.py, rbac.py            ← app/routers/
│           ├── adapters/
│           │   ├── k8s_client.py   live-cluster graph      ← app/k8s_client.py
│           │   ├── sql_store.py    persistence             ← app/database.py + models.py
│           │   └── report_pdf.py   PDF                     ← app/report_service.py
│           └── auth.py                                     ← app/auth.py
├── dashboard/                   Next.js (unchanged location)
│   └── lib/api-types.ts         GENERATED from the API schema (§6)
├── deploy/                      compose (helm moves to kaaval/helm-charts, §2)
└── pyproject.toml               uv workspace root (§5)
```

Every destination maps to a **file that exists today** — this is a move, not a
greenfield. The dividing line is mechanical: if a module imports `fastapi`,
`sqlalchemy`, or `kubernetes`, it belongs in a host under `apps/`, never in
`packages/kaaval-core/`.

## 4. Hexagonal architecture specification

Ports and adapters, grounded in the current functions.

### Domain models (pure data — pydantic, no I/O)

```python
# packages/kaaval-core/kaaval_core/models.py
from pydantic import BaseModel

class RiskContext(BaseModel):
    environment: str = "production"
    data_classification: str = "internal"
    compliance_scope: list[str] = []
    exposure: str = "internal"

class ScoreFactor(BaseModel):
    value: object
    weight: float

class Finding(BaseModel):
    rule_type: str
    severity: str
    title: str
    detail: str
    contextual_score: float | None = None
    score_factors: dict[str, ScoreFactor] | None = None
    remediation: dict | None = None
```

### Domain services (pure functions — the "mathematical risk engine")

These already exist and are already pure — they move verbatim:

```python
# packages/kaaval-core/kaaval_core/scoring.py
def compute_contextual_score(raw_score, severity, context) -> tuple[float, dict]:
    ...   # unchanged from control-plane/app/scoring.py:26

# packages/kaaval-core/kaaval_core/rbac/rules.py
def evaluate_rbac_findings(graph: dict, context: dict) -> list[dict]:
    ...   # unchanged from control-plane/app/rbac_service.py:320

# packages/kaaval-core/kaaval_core/remediation.py
def build_remediation(finding: dict) -> dict:
    ...   # unchanged from control-plane/app/remediation.py:257
```

### Ports (abstract interfaces the domain depends on — inward)

The domain names what it *needs* without knowing who provides it:

```python
# packages/kaaval-core/kaaval_core/ports.py
from typing import Protocol
from uuid import UUID

class ClusterGraphProvider(Protocol):
    """Yields the RBAC graph shape evaluate_rbac_findings() consumes."""
    def get_rbac_graph_data(self) -> dict: ...

class FeedSource(Protocol):
    """Supplies CVE feed entries for matching."""
    def fetch(self) -> list[dict]: ...

class FindingStore(Protocol):
    """Persists / retrieves scan results."""
    def save_rbac_scan(self, tenant_id: UUID, result: dict) -> None: ...
    def latest_rbac_scan(self, tenant_id: UUID) -> dict | None: ...
```

The graph shape is already a stable contract (`get_rbac_graph_data()` and
`build_graph_from_manifests()` both produce it) — that's why two adapters can
feed the same rule engine today.

### Adapters (concrete implementations — live in the hosts, outward)

```python
# apps/kaaval-web/kaaval_web/adapters/k8s_client.py
class K8sClientAdapter:                     # implements ClusterGraphProvider
    def get_rbac_graph_data(self) -> dict:
        ...   # wraps the current app/k8s_client.py:158

# apps/kaaval-cli/kaaval_cli/manifest_source.py
class ManifestGraphProvider:                # implements ClusterGraphProvider
    def __init__(self, path: str): self.path = path
    def get_rbac_graph_data(self) -> dict:
        return build_graph_from_manifests(self.path)   # current app/cli.py:133

# apps/kaaval-web/kaaval_web/adapters/sql_store.py
class SqlFindingStore:                       # implements FindingStore
    def __init__(self, session): self.session = session
    def save_rbac_scan(self, tenant_id, result): ...   # wraps app/database.py + models.py
```

### The application seam that gets cleaner

Today `scan_rbac(db, tenant_id)` (`rbac_service.py:421`) reaches directly for a
`K8sClient`, calls the pure `evaluate_rbac_findings`, then persists via
SQLAlchemy — three layers in one function. Under this structure it becomes a
thin composition that the *host* wires:

```python
def run_rbac_scan(graph_provider: ClusterGraphProvider,
                  store: FindingStore, context: dict, tenant_id) -> dict:
    graph = graph_provider.get_rbac_graph_data()
    findings = evaluate_rbac_findings(graph, context)   # pure core
    result = {"findings": findings, ...}
    store.save_rbac_scan(tenant_id, result)
    return result
```

The web host injects `(K8sClientAdapter, SqlFindingStore)`; the CLI injects
`(ManifestGraphProvider, NullStore)` — same engine, different edges. **The pure
core never learns which one it got.**

## 5. Workspace manifests (uv workspace)

Replace the flat `control-plane/requirements.txt` with a
[uv workspace](https://docs.astral.sh/uv/concepts/workspaces/) — one lockfile,
three members, dependency isolation enforced by packaging.

```toml
# pyproject.toml (workspace root)
[tool.uv.workspace]
members = ["packages/*", "apps/*"]

[tool.uv.sources]
kaaval-core = { workspace = true }
```

```toml
# packages/kaaval-core/pyproject.toml  — the domain: pydantic + stdlib ONLY
[project]
name = "kaaval-core"
dependencies = ["pydantic>=2.13", "pyyaml>=6.0"]
```

```toml
# apps/kaaval-cli/pyproject.toml  — light host: core + cluster read, NO web/db
[project]
name = "kaaval-cli"
dependencies = ["kaaval-core", "kubernetes==36.0.2", "pyyaml==6.0.3"]
[project.scripts]
kaaval = "kaaval_cli.main:main"
```

```toml
# apps/kaaval-web/pyproject.toml  — heavy host: core + everything stateful
[project]
name = "kaaval-web"
dependencies = [
  "kaaval-core", "fastapi==0.139.0", "uvicorn[standard]==0.51.0",
  "sqlalchemy==2.0.51", "psycopg2-binary==2.9.12", "PyJWT==2.13.0",
  "bcrypt==5.0.0", "python-multipart==0.0.32", "httpx==0.28.1",
  "apscheduler==3.11.3", "reportlab==5.0.0", "cryptography==49.0.0",
]
```

The payoff is visible in the split: **`kaaval-core` has two dependencies**;
`kaaval-cli` adds only the Kubernetes client; the fifteen heavy libs sit only in
`kaaval-web`. A `pip check` in the core's environment fails if anyone imports
`fastapi` from the domain — the boundary is now mechanically enforced, not a
convention. Right-sizing note: uv workspaces are the correct tool; resist adding
heavier monorepo machinery (Bazel, Nx) — the project isn't that big.

## 6. Contract-first automation (API schema → TypeScript)

Today the dashboard **hand-writes** its types — `dashboard/app/rbac/page.tsx`
declares `interface RBACFinding`, `ScoreFactor`, `Subject`, `RBACScan` by hand.
They can (and will) drift from what the API actually returns.

FastAPI already emits an OpenAPI schema from the Pydantic models. Generate the TS
from it:

```makefile
# Makefile
api-types:  ## regenerate dashboard types from the live API schema
	@python -c "import json; from kaaval_web.main import app; \
	  open('dashboard/openapi.json','w').write(json.dumps(app.openapi()))"
	@cd dashboard && npx openapi-typescript openapi.json -o lib/api-types.ts
```

The dashboard imports `RBACFinding` from `lib/api-types.ts` instead of declaring
it. A CI step runs `make api-types` and fails if `git diff` is non-empty — so a
backend model change that isn't reflected in the frontend types turns the build
**red** instead of silently shipping a mismatch. Same discipline as the Kyverno
digest check we already run.

## 7. Targeted pipeline rules (path-filtered CI)

`ci.yml` runs **both** the control-plane suite and the dashboard build on every
PR — a one-line docs change pays for the full matrix. Filter by path:

```yaml
# .github/workflows/ci.yml (sketch)
on:
  pull_request:
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      core: ${{ steps.f.outputs.core }}
      web:  ${{ steps.f.outputs.web }}
      dash: ${{ steps.f.outputs.dash }}
    steps:
      - uses: dorny/paths-filter@<pin>
        id: f
        with:
          filters: |
            core: ['packages/kaaval-core/**']
            web:  ['apps/kaaval-web/**', 'packages/kaaval-core/**']
            dash: ['dashboard/**']
  control-plane:
    needs: changes
    if: ${{ needs.changes.outputs.web == 'true' }}
    ...
  dashboard:
    needs: changes
    if: ${{ needs.changes.outputs.dash == 'true' }}
    ...
```

**The branch-protection gotcha (must handle, not naive-filter):** `control-plane`
and `dashboard` are **required** status checks on `main`. A plain `paths:` filter
at the workflow level makes the job *not report at all* on an unaffected PR —
which GitHub treats as **pending forever**, blocking merge. The correct pattern is
the `dorny/paths-filter` gate above (the job still runs and short-circuits to
success via `if:`), **or** GitHub's "require checks only if they run" setting.
A docs-only PR then legitimately skips both without wedging the merge. This
interaction is the whole reason path-filtering isn't a two-line change.

## 8. Refactoring roadmap — phased, contributor-safe

Ordered by **value now × disruption avoided**, not by architectural tidiness.
Nothing here blocks the three in-flight contributor PRs or the Sandbox push.

### Phase 1 — non-breaking wins (do these first; no restructure)
- **Path-filtered CI** (§7) — pure win, touches only `ci.yml`, handles the
  required-check gotcha. Faster PRs immediately.
- **Extract `kaaval/helm-charts`** — unblocks the real Helm chart ([#8](https://github.com/kaaval/kaaval/issues/8))
  in its own repo with independent tagging + Artifact Hub. Doesn't touch app code.
- **Contract-first types** (§6) — add the generator + CI drift-check; the
  dashboard stops hand-maintaining types. Isolated to `dashboard/` + a Makefile
  target.

None of these move a single Python module, so no contributor's open PR conflicts.

### Phase 2 — internal hexagonal refactor (behind a stable surface)
- Introduce `packages/kaaval-core/` and move the **already-pure** modules
  (`scoring.py`, `remediation.py`, the pure parts of `rbac_service.py` /
  `cve_service.py`) into it, re-exporting from the old import paths so nothing
  external breaks.
- Define `ports.py`; wrap `k8s_client.py`, `database.py`+`models.py`,
  `report_service.py` as adapters; refactor `scan_rbac()` into the injected
  `run_rbac_scan()` seam (§4).
- **Tests are the safety net** — `test_rbac_service.py` / `test_cli.py` /
  `test_smoke.py` must stay green throughout; the refactor is done when they pass
  unchanged against the new structure. Do this in one focused window, not
  interleaved with feature PRs.

### Phase 3 — full workspace split + Action repo (gated on real need)
- Split `apps/kaaval-cli` and `apps/kaaval-web` into the uv workspace (§5);
  update Dockerfiles + CI to build per-app.
- **Extract `kaaval/github-action`** when Marketplace publication ([#34](https://github.com/kaaval/kaaval/issues/34))
  actually happens — the standalone repo is a Marketplace requirement, not a
  reason on its own.
- Gate: only worthwhile once the CLI and web genuinely diverge in dependencies or
  release cadence enough to justify two packages. Until then, Phase 2's internal
  boundary already delivers the testability and the Go-engine contract.

## When to *not* do this

If it isn't Phase 1, and there's no concrete pull for it (a contributor blocked by
the flat layout, the Go engine actually starting, Marketplace publication going
live), **defer it**. The pure core already exists; the discipline that matters —
domain imports no infrastructure — can be protected with a single import-lint rule
long before the folders move. Structure should follow a real constraint, not
precede it.
