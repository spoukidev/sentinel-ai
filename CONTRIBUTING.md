# Contributing

Start with `docs/implementation-plan.md` and the threat model. Create one focused branch for a vertical slice. Use conventional commit messages when Git is initialized. Do not claim roadmap modules are implemented.

1. Install dependencies and generate an ignored local `.env`.
2. Run migrations and seed the synthetic workspace.
3. Add behavior tests for authorization, tenant boundaries and changed business logic.
4. Run Pytest, Ruff, frontend lint/typecheck/build and relevant browser tests.
5. Add and review an Alembic migration for model changes; never edit an applied revision.
6. Update the README capability table and API examples.

Never commit secrets, `.env`, local databases or real security logs. Use only reserved IPs/domains and fictional identities. Rule contributions must use the safe DSL; no eval, shell execution, active scanning or automatic response. Frontend controls must perform real actions, expose loading/errors and remain keyboard-accessible. Update dependency lockfiles together with dependency declarations.
