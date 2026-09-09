"""Generate local development settings without exposing secrets in output."""
import secrets
from pathlib import Path

root = Path(__file__).resolve().parent.parent
destination = root / '.env'
if destination.exists():
    print('.env exists; preserved. Set any missing values using .env.example.')
else:
    destination.write_text('\n'.join([
        f'POSTGRES_PASSWORD={secrets.token_urlsafe(32)}',
        f'JWT_SECRET={secrets.token_urlsafe(48)}',
        f'DEMO_PASSWORD={secrets.token_urlsafe(18)}',
        'DEMO_MODE=true', 'APP_ORIGIN=http://localhost:3000', 'COOKIE_SECURE=false',
        'DATABASE_URL=sqlite:///./sentinel.db', ''
    ]), encoding='utf-8')
    print('Created ignored .env with random development credentials. Read DEMO_PASSWORD locally to sign in.')
