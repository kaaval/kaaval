import os
from contextvars import ContextVar
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://kaaval:password@127.0.0.1:5432/kaaval_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Request-scoped tenant context — set by auth middleware, consumed by get_db
_current_tenant_id: ContextVar[str] = ContextVar(
    "_current_tenant_id",
    default="00000000-0000-0000-0000-000000000000",
)


def set_tenant_context(tenant_id: str) -> None:
    _current_tenant_id.set(tenant_id)


def get_db():
    db = SessionLocal()
    try:
        tenant_id = _current_tenant_id.get()
        db.execute(text(f"SET app.current_tenant = '{tenant_id}'"))
        yield db
    finally:
        db.close()
