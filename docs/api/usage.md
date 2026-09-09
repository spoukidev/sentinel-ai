# API usage

Base URL: `http://localhost:8000/api/v1`. Interactive schemas: `/docs`; machine-readable schemas: `/openapi.json`. UTC event timestamps must include an offset. Responses expose stored UTC timestamps without a suffix; the UI interprets them as UTC.

## Authenticate

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Origin: http://localhost:3000' \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@sentinel.example","password":"YOUR_LOCAL_DEMO_PASSWORD"}'
```

Keep returned bearer access tokens private. Pass `Authorization: Bearer <access_token>` to data endpoints. All authentication mutations require `Origin: http://localhost:3000`; refresh also requires the refresh cookie. Logout requires a valid bearer token and revokes all sessions. Login has a ten-attempts/minute process-local IP limit.

## Ingest events

```json
{
  "events": [{
    "timestamp": "2026-01-01T10:00:00Z",
    "source": "dns",
    "category": "network",
    "event_type": "dns_query",
    "hostname": "edge-01",
    "username": "demo-user",
    "action": "query",
    "outcome": "success",
    "raw_event": "Harmless synthetic DNS example",
    "parsed_metadata": {"domain": "blocked.example"}
  }]
}
```

POST to `/events/batch`. Success: HTTP 201 with `accepted` and `duplicates`. A single invalid record rejects the complete batch with HTTP 422; no partial import. Organization is derived from authentication. Single-event POST `/events` accepts the same event without its wrapper.

## Search and investigate

- GET `/alerts?severity=critical&status=new&sort=risk&page_number=1&page_size=20`
- GET `/alerts/{id}` returns evidence, notes, history and rule-authored response guidance.
- PATCH `/alerts/{id}` with `{"status":"investigating","assignee":null,"false_positive_reason":""}`.
- POST `/alerts/{id}/notes` with `{"body":"Reviewed synthetic source with asset owner."}`.
- GET `/assets?q=ws-&sort=hostname&page_number=1`.
- GET `/events?source=windows&q=login&page_number=1`.
- GET `/organizations/members`; administrator PATCH `/organizations/members/{user_id}` with `{"role":"viewer"}`. Self-role changes are refused.
- GET/POST `/rules`; administrator PUT/DELETE `/rules/{id}`. Rules with historical alerts must be disabled instead of deleted.
- POST `/assets/import` with `{"content":"hostname,ip_address\nnew-host,192.0.2.240"}`.

List responses use `{items,total,page,page_size}`. Rule listings are capped at the enforced 100-rule workspace limit. Asset and alert sorts are allowlisted; unrecognized sort values use the default. Not all endpoints support every filter: consult OpenAPI.

Errors use `detail`; validation errors also include safe `errors` entries without the submitted values. Normal responses include a generated `X-Request-ID`. No cross-organization resource existence is revealed: scoped access returns 404. Important writes and audit records share the transaction.
