"""PostgreSQL integration check: concurrent identical safe events create one alert."""
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
from dotenv import dotenv_values


async def main():
    env = dotenv_values(Path(__file__).resolve().parent.parent / '.env')
    async with httpx.AsyncClient(base_url='http://localhost:8000/api/v1', timeout=30, headers={'Origin':'http://localhost:3000'}) as client:
        response = await client.post('/auth/login', json={'email':'analyst@sentinel.example','password':env['DEMO_PASSWORD']})
        response.raise_for_status()
        client.headers['Authorization'] = 'Bearer ' + response.json()['access_token']
        hostname = 'concurrency-' + uuid4().hex[:10]
        event = {'timestamp':(datetime.now(timezone.utc)-timedelta(seconds=5)).isoformat(),
                 'source':'dns','category':'network','event_type':'concurrency_probe','hostname':hostname,
                 'username':'demo-probe','action':'query','outcome':'success','parsed_metadata':{'domain':'blocked.example'},
                 'raw_event':'Harmless synthetic concurrency verification'}
        responses = await asyncio.gather(*(client.post('/events', json=event) for _ in range(8)))
        for item in responses:
            item.raise_for_status()
        assert sum(item.json()['accepted'] for item in responses) == 1
        assert sum(item.json()['duplicates'] for item in responses) == 7
        alerts = await client.get('/alerts', params={'q':hostname})
        alerts.raise_for_status()
        assert alerts.json()['total'] == 1
        print('Eight concurrent requests: one accepted event, seven duplicates, one alert. PostgreSQL transaction serialization verified.')


asyncio.run(main())
