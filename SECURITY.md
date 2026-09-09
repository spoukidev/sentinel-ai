# Security policy

SentinelAI v0.1 is a defensive portfolio foundation for local synthetic demonstrations. It has not received an independent security audit and must not be exposed to untrusted networks without hardening.

## Reporting a vulnerability
Do not post credentials, exploitable tenant data or sensitive logs in a public issue. Before publishing, the repository owner must enable GitHub private vulnerability reporting and publish a monitored security contact. Until then, use a private channel to the repository owner; no unmonitored address is provided here. Include affected version, minimal harmless reproduction, expected/actual behavior and impact. Never test against systems you do not own or have authorization to assess.

## Supported version
Only the current development branch is maintained. No response-time SLA is claimed.

## Controls
Argon2 password hashing; 15-minute signed access tokens; seven-day hashed, rotating refresh sessions; session revocation on logout; authorization resolved on every API request; organization-scoped queries; safe rule DSL; validated references; strict Pydantic schemas; bounded inputs; no shell execution or automatic URL requests; text rendering of logs; parameterized SQL; local-only published Compose ports; non-root application containers.

## Release checklist
- [ ] Run CI and review dependency/secret scan findings on the final commit.
- [x] Verify PostgreSQL migrations and concurrent identical-event ingestion with Docker running.
- [ ] Configure HTTPS, Secure cookies, exact origin and a restrictive network boundary.
- [ ] Disable demo mode and remove demo accounts outside evaluation.
- [ ] Add shared rate limiting before multiple API workers or proxy scaling.
- [ ] Replace permissive inline-script CSP with per-request nonces before Internet exposure.
- [ ] Establish retention, encrypted backups, monitoring and a private reporting contact.
- [ ] Review the [threat model](docs/threat-model/threat-model.md).

Secrets generated during setup are stored only in ignored `.env`. Do not attach that file to bug reports. HTTP access logs do not include bodies. Raw event content can contain secrets if operators ingest them: Phase 1 has no automatic redaction or retention worker. Use only the synthetic demo data.
