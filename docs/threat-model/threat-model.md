# SentinelAI threat model — Phase 1

## Scope and trust boundaries
Assets: credentials/session material, tenant assets/events, detection rules, alert evidence, notes and audit records. Actors: unauthenticated visitors, viewers, analysts, administrators, database operators and dependency maintainers. Browser input and ingested logs are untrusted. API authorization is the boundary between organizations. Database operators remain trusted; no PostgreSQL row-level security is configured.

| Threat | Implemented control | Remaining risk / next step |
|---|---|---|
| Broken access control | Live membership role checks; writers/admin dependencies | Route tests must expand as endpoints are added |
| Cross-tenant object access | Organization filters on reads/writes; scoped assignee checks; isolation tests | Database itself lacks RLS and composite tenant FKs |
| SQL/code injection | SQLAlchemy parameters; allowlisted rule fields and operators | Future rule operators require security review |
| XSS in logs/notes | React text only; no HTML execution; security headers | CSP allows inline scripts for Next; nonce-based policy planned |
| CSRF/session fixation | Access token in memory; HttpOnly SameSite cookie; exact Origin on all authentication mutations; rotating refresh session | SameSite is defense in depth; XSS can still act within the origin |
| Weak passwords | Argon2 and 12-character registration minimum; random demo setup password | No breached-password screening, MFA, verification or recovery |
| Token theft | Short access expiry; hashed refresh storage; every request validates live session; logout revokes sessions | XSS could act as user; HTTPS and Secure cookie required outside localhost |
| Brute force / abuse | Ten auth attempts per IP/minute, generic login errors | Process-local limiter and shared proxy IP; add Redis and trusted proxy policy |
| Malicious upload | No file upload endpoint; bounded CSV text validates every row before insertion | CSV import limited to 100 rows; exported JSON is text |
| Prompt injection | No AI/provider execution in this release; safe static rules | Phase 3 must isolate/redact evidence and forbid tool execution |
| Sensitive-data leakage | No password/token serialization; safe audit metadata; validation errors omit submitted inputs | Raw event data is retained as supplied; synthetic input required |
| Dependency compromise | Lockfiles, CI audit, reproducible builds | Review updates and action pins; no guarantee of zero vulnerabilities |
| Insecure logging | No bodies/credentials in audit metadata or application logs | Infrastructure must avoid debug/body logging |
| CORS misconfiguration | Same-origin proxy; no permissive CORS middleware | Alternate frontend origins need explicit review |
| SSRF | No event-driven network requests; fixed API proxy target | Future AI provider URL configuration needs operator validation |
| Unsafe redirects | Fixed internal login/home routes | No user-controlled return URL accepted |
| Mass assignment | Extra request fields forbidden; tenant/actor IDs assigned server-side | DB integrity still relies on route checks for some references |
| Oversized inputs/DoS | 2 MB middleware body bound, 100-event batches, metadata/log limits, 100 rules, capped candidates | Slow bodies, high request rates and historical dashboard scans need proxy limits and load testing |
| Duplicate ingestion races | Per-organization PostgreSQL lock and unique fingerprints; unique alert keys; eight-request concurrency check passed | SQLite evaluation mode is single-writer; concurrent rule changes and other mutation races need broader testing |
| Audit tampering | No audit mutation API; all ordinary mutations append records transactionally | Database administrators can modify records; immutable sink deferred |
| Loss/retention | Persistent PostgreSQL volume; seed is idempotent | No backup automation, retention policy enforcement or recovery SLA |

## Practical safety boundaries
The generator only prints JSON. Example command indicators are inert text. No malware, endpoint agents, offensive testing, credential collection, attachment opening or containment automation exists. MITRE labels describe hypotheses, never confirmed attacks.

## Verification strategy
Negative tests exercise missing/invalid auth, viewer writes, foreign asset/alert/rule access, tenant injection, invalid timestamps/IPs, oversized requests, unsafe rule fields, expired/revoked sessions and CSRF origin mismatch. Browser tests check persisted actions and display of safe data. CI adds PostgreSQL migration and container build coverage. See the verification record for checks actually executed locally.
