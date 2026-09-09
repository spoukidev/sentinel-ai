# Five-minute evaluation

Start the app using the README and sign in with `analyst@sentinel.example` and the locally generated development password.

1. **Overview (45 sec).** Explain that metrics and charts query the database. The seed creates 572 normalized events and 40 real rule matches; it does not insert fabricated alert rows.
2. **Alert investigation (60 sec).** Filter Critical. Open a role-assignment or DNS alert. Read Why this matched, expand the evidence and follow the MITRE link.
3. **Analyst decision (45 sec).** Assign Demo Analyst, select Investigating and save. Add a note. Reload and reopen the alert to show persistence. False-positive decisions require a reason.
4. **Event ingestion (45 sec).** Submit the prefetched harmless DNS JSON. Repeat the same payload to show duplicate protection. New event data is evaluated within its transaction.
5. **Asset/rule context (45 sec).** Inspect Assets and Coverage. As administrator, toggle a rule and inspect the audit record. A viewer can read but cannot mutate data.
6. **Export (20 sec).** Export overview JSON. This is a dashboard snapshot, not an incident report.

## Safe scenarios
Repeated failed logins, synthetic new-country signal, outbound volume signal, repeated missing resources, demo-blocklisted DNS, administrator assignment, inert command indicator, disabled-control audit event, synthetic travel flag and benign baseline. One alert is deliberately documented as a false positive.

No real-location travel calculation or failed-login-then-success correlation is claimed. Those sequence and baseline behaviors are roadmap items. Incident, AI, phishing and anomaly demonstration steps are deferred until the corresponding modules exist.

The event generator can be run with `python demo/generators/events.py`; paste its JSON into Events. It prints data and never accesses the network. All addresses are documentation addresses.
