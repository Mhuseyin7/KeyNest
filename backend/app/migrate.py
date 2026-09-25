"""Bootstrap schema for a new self-hosted instance.

Use a reviewed migration system before upgrading an existing production database.
"""
from .db import engine
from .models import Base

if __name__ == "__main__":
    Base.metadata.create_all(engine)

