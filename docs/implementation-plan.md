# SentinelAI implementation plan

## Repository inspection
The workspace was empty on 2026-09-09. No Git repository, existing license, or AGENTS.md was found. Python 3.14, Node 24, Git and Docker CLI are installed. No existing work needs replacement.

## Phase 1 — functional foundation
1. Create a Next.js / TypeScript frontend and FastAPI / SQLAlchemy backend monorepo.
2. Define organization, user, membership, session, asset, event, rule, alert, evidence, note, status-history and audit tables. Create an Alembic initial migration.
3. Implement Argon2 authentication with short-lived bearer access tokens, rotating opaque refresh tokens, session revocation, RBAC and organization-scoped queries. Registration creates a separate organization.
4. Implement validated asset CRUD and CSV import; paginated event search and atomic batch ingestion with deduplication.
5. Implement structured, bounded detection rules with event-time windows, thresholds, evidence and duplicate-alert suppression. Seed 20 assets, 500+ events, ten rules and 25+ real detections.
6. Build responsive login, dashboard, alert investigation, asset, event, rule, coverage, audit and settings screens. Every visible action must call real APIs.
7. Add Docker Compose with PostgreSQL, health checks, environment examples, CI, tests, threat model and developer documentation.
8. Run backend tests/lint, frontend lint/typecheck/build and browser/API smoke checks. Record exact results and constraints.

## Later slices
Phase 2: incidents, checklist tasks, timeline, exports and complete investigation E2E tests.
Phase 3: Ollama/OpenAI-compatible providers and deterministic fallback, static phishing analysis, explainable anomaly signals.
Phase 4: expanded accessibility testing, screenshots, release review and documentation for the completed scope.

## Technical decisions and risks
- PostgreSQL is the deployment database; SQLite exists only for tests and quick local evaluation. Verify the PostgreSQL path separately when Docker is running.
- Single synchronous API worker in Phase 1; bounded ingestion is transactional. Redis/Celery are deferred until asynchronous processing is implemented; no placeholder services.
- Refresh token is an HttpOnly SameSite cookie; access token stays in browser memory. Same-origin Next.js proxy avoids broad CORS. Mutation requests using cookies require an allowed Origin.
- Ten structured demonstration rules use allowlisted fields/operators; never evaluate code. This engine is Sigma-inspired, not a Sigma implementation.
- Concurrency: ingestion serialized per organization via database row locking on PostgreSQL. SQLite development is single-writer only.
- Login limiter is process-local in this phase; multiple workers require a shared limiter before production deployment.
- No paid infrastructure, external AI, live collection, active response, or deployment is required.

## Structure
`apps/api`: API, models, migrations, seed and tests. `apps/web`: UI and browser tests. `packages/detection-rules`: safe rule catalog. `demo`: synthetic examples. `infrastructure/docker`: container configuration. `docs`: architecture, API, threat model, demo and verification.

## Phase 1 outcome
Completed the functional foundation and verified both local SQLite and Docker/PostgreSQL operation. Thirteen backend tests and four browser workflows pass, frontend lint/typecheck/build and backend lint/format checks pass, both images build, migrations match the schema, and concurrent identical ingestion yields one event and one alert. Seed creates 572 events and 40 real alerts. See `docs/verification.md` for exact commands and limitations.

Scope adjustments: application Dockerfiles live beside their apps; infrastructure guidance lives in `infrastructure/README.md`. Notes, status history, audit UI and rule coverage were brought into the foundation to make investigations reviewable. Incident management and intelligent analysis remain later slices. The roadmap is explicit; this is not a declaration that all four phases are complete.
