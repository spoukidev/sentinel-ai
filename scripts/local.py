"""Local development and verification entry point; credentials stay in child environment."""
import os
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values

root = Path(__file__).resolve().parent.parent
env = {**os.environ, **{k: v for k, v in dotenv_values(root / '.env').items() if v is not None}}
api_dir = root / 'apps' / 'api'
web_dir = root / 'apps' / 'web'
action = sys.argv[1] if len(sys.argv) > 1 else 'api'
commands = {
    'api': ([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'], api_dir),
    'seed': ([sys.executable, '-m', 'app.seed'], api_dir),
    'migrate': ([sys.executable, '-m', 'alembic', 'upgrade', 'head'], api_dir),
    'e2e': (['npm.cmd' if os.name == 'nt' else 'npm', 'run', 'test:e2e'], web_dir),
}
if action not in commands:
    raise SystemExit('Usage: python scripts/local.py [api|seed|migrate|e2e]')
command, cwd = commands[action]
raise SystemExit(subprocess.call(command, cwd=cwd, env=env))
