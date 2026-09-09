"""Exercise the running API without printing credentials or bearer tokens."""
from pathlib import Path

import httpx
from dotenv import dotenv_values

root = Path(__file__).resolve().parent.parent
env = dotenv_values(root / '.env')
with httpx.Client(base_url='http://localhost:8000/api/v1', headers={'Origin': 'http://localhost:3000'}) as client:
    ready = client.get('/health/ready')
    ready.raise_for_status()
    login = client.post('/auth/login', json={'email':'analyst@sentinel.example', 'password':env['DEMO_PASSWORD']})
    login.raise_for_status()
    client.headers['Authorization'] = 'Bearer ' + login.json()['access_token']
    dashboard = client.get('/dashboard')
    dashboard.raise_for_status()
    counts = dashboard.json()
    assert counts['events'] >= 572 and counts['monitored_assets'] >= 20
    alerts = client.get('/alerts').json()
    assert alerts['total'] >= 40
    detail = client.get('/alerts/' + alerts['items'][0]['id']).json()
    assert detail['evidence']
    members = client.get('/organizations/members').json()
    assert len(members) == 3
    print(f"Ready; authenticated analyst; {counts['events']} events; {counts['monitored_assets']} assets; {alerts['total']} alerts; evidence and members verified.")
