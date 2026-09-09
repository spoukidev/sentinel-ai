# Verification record — 2026-09-09

## Verified foundation

The workspace began empty. The working Phase 1 application was built and exercised locally on Windows with Python 3.14 and Node 24, then built and started in Docker using Python 3.12, Node 24 and PostgreSQL 17. No public deployment or GitHub push was performed.

| Check | Result |
|---|---|
| Backend behavior suite | 13 passed on host and in the API container |
| Ruff lint and formatting | Passed |
| Frontend ESLint | Passed |
| Strict TypeScript | Passed |
| Next.js production build | Passed on Windows and Linux Docker build |
| Browser workflows on local SQLite setup | 4 passed |
| Browser workflows on Docker/PostgreSQL setup | 4 passed |
| Initial migration and Alembic drift check | Passed on SQLite and PostgreSQL |
| Docker API and web images | Both built successfully |
| Compose startup | PostgreSQL and API healthy; frontend serves production app |
| PostgreSQL seed and smoke test | 572 events, 20 assets, 40 alerts, evidence and three members verified |
| PostgreSQL concurrent ingestion | Eight simultaneous identical requests: 1 accepted event, 7 duplicates, 1 alert |
| npm dependency audit | Zero reported vulnerabilities at check time |
| Python pinned-dependency audit | No known vulnerabilities found at check time |
| Basic source secret-pattern scan | 51 inspected source/document/config files, zero matches; not a replacement for full secret scanning |

The browser tests exercise login, real alert filters and evidence, saved status and note, event ingestion, asset creation/search, controlled API failure/retry, empty results, tablet overflow and logout/protected access. The screenshot in `docs/screenshots/overview.png` is captured from the live API-backed interface. Test runs intentionally add synthetic events/assets/notes, so screenshots can show counts above the initial seed.

## Exact commands used

From repository root unless a directory is stated:

```powershell
python scripts/setup-env.py
.\.venv\Scripts\python scripts/local.py migrate
.\.venv\Scripts\python scripts/local.py seed
.\.venv\Scripts\python scripts/local.py api
.\.venv\Scripts\python scripts/local.py e2e
.\.venv\Scripts\python scripts/verify-demo.py
.\.venv\Scripts\python scripts/verify-concurrency.py
.\.venv\Scripts\python -m pip_audit -r apps/api/requirements.lock.txt --no-deps --disable-pip --timeout 60
docker compose config --quiet
docker compose build
docker compose up -d --wait
docker compose ps
docker compose exec -T api alembic check
docker compose exec -T api pytest -q
docker compose exec -T api ruff check .
docker compose exec -T api ruff format --check .
```

In `apps/api`:

```powershell
..\..\.venv\Scripts\python -m pytest -q
..\..\.venv\Scripts\python -m ruff check .
..\..\.venv\Scripts\python -m ruff format --check .
..\..\.venv\Scripts\python -m alembic upgrade head
..\..\.venv\Scripts\python -m alembic check
```

In `apps/web`:

```powershell
npm.cmd install
npm.cmd install --package-lock-only --ignore-scripts
npm.cmd run lint
npm.cmd run typecheck
npm.cmd run build
npm.cmd run start
npx.cmd playwright install chromium
```

## Corrections made during verification

- Downloaded dependencies with network permission after sandbox network access failed.
- Fixed frontend lint issues, explicit status control labeling and modal focus behavior.
- Disabled chart animation for complete/reproducible rendering.
- Switched local production serving to the Next.js standalone server and pinned dependency versions.
- Stopped the serving process before rebuilding after Windows reported a locked standalone directory.
- Started Docker Desktop and verified the real PostgreSQL stack after it was initially unavailable.
- Retried a timed-out PyPI audit; the retry completed successfully.

## Known limits of this verification

Two upstream Starlette/httpx/AnyIO test-client deprecation warnings remain; they do not fail the tests. Initial non-root container testing also exposed an unwritable pytest cache, addressed by moving tool caches to `/tmp`. Hosted GitHub Actions and gitleaks have been configured but not executed on a remote repository. No Internet deployment, performance/load certification, full accessibility audit or independent penetration test has been performed. Rule evaluation concurrency was exercised for duplicate ingestion, not every possible concurrent mutation.

Phase 2 incidents and Phase 3 AI/phishing/anomaly modules remain unimplemented. Phase 4 has initial documentation, responsive styling, browser screenshots and CI configuration, but has not been declared complete.
