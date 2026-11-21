"""Keep Kaaval's access/refresh token contract across PyJWT security updates."""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest

from app import auth


@pytest.fixture(autouse=True)
def signing_keys(monkeypatch):
    monkeypatch.setattr(auth, "SECRET_KEY", "access-test-key-" + "a" * 32)
    monkeypatch.setattr(auth, "REFRESH_SECRET_KEY", "refresh-test-key-" + "r" * 32)


def _claims(token_type="access", expired=False):
    delta = timedelta(minutes=-1 if expired else 5)
    return {"sub": "alice", "type": token_type, "exp": datetime.now(timezone.utc) + delta}


def test_access_token_authenticates_user_and_sets_tenant(monkeypatch):
    user = SimpleNamespace(username="alice", tenant_id="tenant-a")
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = user
    set_tenant = MagicMock()
    monkeypatch.setattr(auth, "set_tenant_context", set_tenant)

    token = auth.create_access_token({"sub": user.username})
    assert asyncio.run(auth.get_user_from_token(token, db=db)) is user
    set_tenant.assert_called_once_with("tenant-a")


@pytest.mark.parametrize("case", ["expired", "wrong-key", "wrong-algorithm", "unsigned", "malformed", "refresh"])
def test_invalid_access_tokens_are_rejected_before_user_lookup(case):
    if case == "expired":
        token = auth.create_access_token({"sub": "alice"}, expires_delta=timedelta(minutes=-1))
    elif case == "wrong-key":
        token = jwt.encode(_claims(), "different-test-key-" + "x" * 32, algorithm=auth.ALGORITHM)
    elif case == "wrong-algorithm":
        token = jwt.encode(_claims(), auth.SECRET_KEY, algorithm="HS384")
    elif case == "unsigned":
        token = jwt.encode(_claims(), "", algorithm="none")
    elif case == "refresh":
        token = auth.create_refresh_token({"sub": "alice"})
    else:
        token = "not-a-jwt"

    db = MagicMock()
    assert asyncio.run(auth.get_user_from_token(token, db=db)) is None
    db.query.assert_not_called()


def test_refresh_token_roundtrip():
    token = auth.create_refresh_token({"sub": "alice"})
    assert auth.decode_refresh_token(token) == "alice"


@pytest.mark.parametrize("case", ["expired", "wrong-key", "wrong-type", "access", "malformed"])
def test_invalid_refresh_tokens_are_rejected(case):
    if case == "expired":
        token = jwt.encode(_claims("refresh", expired=True), auth.REFRESH_SECRET_KEY, algorithm=auth.ALGORITHM)
    elif case == "wrong-key":
        token = jwt.encode(_claims("refresh"), auth.SECRET_KEY, algorithm=auth.ALGORITHM)
    elif case == "wrong-type":
        token = jwt.encode(_claims("access"), auth.REFRESH_SECRET_KEY, algorithm=auth.ALGORITHM)
    elif case == "access":
        token = auth.create_access_token({"sub": "alice"})
    else:
        token = "not-a-jwt"

    assert auth.decode_refresh_token(token) is None
