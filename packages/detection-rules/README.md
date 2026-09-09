# Detection catalog

The executable, Pydantic-validated catalog is `apps/api/app/seed.py::catalog`. `catalog.json` is a generated portable copy. Rules accept only explicit field and operator allowlists. All conditions use AND semantics. Thresholds group by organization, source, hostname and username within an event-time window.

The ten examples deliberately use safe indicators. Travel and new-country rules consume synthetic boolean signals; they do not compute geolocation. The informational privileged-login rule is a contextual signal, not an assertion of compromise. ATT&CK mappings describe possible behavior, not confirmed attribution.

Limitations: no full Sigma compatibility, sequence correlation, new-country baseline computation, regex, user code, or network access. A maximum of 1,000 candidate events per group/window bounds evaluation. This may undercount high-volume windows. Late events across separate batches do not trigger retrospective replay. Enabling or changing rules applies to future ingestion only.
