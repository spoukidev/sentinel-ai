# Architecture

```mermaid
flowchart LR
  Analyst --> Next[Next.js UI / same-origin API proxy]
  Next --> API[FastAPI / authentication / RBAC]
  API --> DB[(PostgreSQL)]
  Synthetic[Synthetic JSON events] --> API
  API --> Engine[Transactional rule engine]
  Engine --> DB
```

```mermaid
flowchart LR
  Validate --> Deduplicate --> Store --> MatchConditions --> CountWindow --> Alert --> Evidence
```

```mermaid
erDiagram
  Organization ||--o{ OrganizationMember : includes
  User ||--o{ OrganizationMember : joins
  User ||--o{ Session : authenticates
  Organization ||--o{ Asset : owns
  Organization ||--o{ SecurityEvent : receives
  Organization ||--o{ DetectionRule : configures
  DetectionRule ||--o{ Alert : triggers
  Alert ||--o{ AlertEvidence : references
  SecurityEvent ||--o{ AlertEvidence : supports
  Alert ||--o{ AlertNote : annotated
  Alert ||--o{ AlertStatusHistory : tracks
  Organization ||--o{ AuditLog : records
```

All resource reads and writes include the authenticated membership's organization ID. Clients cannot select a tenant through request bodies. Foreign references are checked within the same organization. UUIDs are identifiers, never authorization controls. Events are immutable; deleting assets detaches historical alert references. Accounts own one workspace in Phase 1; switching organizations and invitations are deferred.

Planned Phase 2 workflow (not implemented in Phase 1):
```mermaid
flowchart LR
  Alert --> Incident --> Tasks --> Investigation --> Resolution --> Report
```

Planned Phase 3 AI boundary (not implemented in Phase 1):
```mermaid
flowchart LR
  Evidence[Untrusted evidence] --> Redact[Redact and bound context]
  Redact --> Provider[Local AI or deterministic fallback]
  Provider --> Review[Analyst verification]
  Review --> Manual[Explicit manual decisions]
```
