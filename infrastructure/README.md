# Local infrastructure

The root Compose file defines PostgreSQL, API and web services. Database health gates API startup; API readiness gates the frontend. Only loopback ports are published. API and web containers run as non-root users. There is no automated external deployment.

For optional self-hosting, use an HTTPS reverse proxy on a host you control, enable Secure cookies, configure the exact origin, disable demo accounts, establish backups and monitoring, and add a shared limiter before increasing workers. Review SECURITY.md before exposing the app. No paid host is required or provisioned.
