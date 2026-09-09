"""Print harmless JSON for manual ingestion; never contacts a host."""
import json
from datetime import datetime, timedelta, timezone

base = datetime.now(timezone.utc) - timedelta(minutes=2)
print(json.dumps({'events': [dict(timestamp=(base + timedelta(seconds=i * 10)).isoformat(),
    source='windows', category='authentication', event_type='synthetic_failed_login',
    hostname='ws-01', username='demo-user', source_ip='198.51.100.20',
    action='login', outcome='failure', raw_event='Harmless synthetic log') for i in range(6)]}, indent=2))
