from .db import settings
from .seed import seed

if settings.demo_mode:
    seed()
