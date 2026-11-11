import re
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from securedb.app import create_app
from securedb.audit.log import Actor, AuditRecord, list_entries
from securedb.config import Settings
from securedb.console import auth
from securedb.console.routes import PRE_LOGIN_COOKIE, SESSION_COOKIE
from securedb.crypto.local import LocalKeyProvider
from securedb.db.models import ApiKey, TenantKey, Token
from securedb.db.session import Database
from securedb.tenants.api_keys import authenticate
from securedb.tenants.service import create_tenant

TEST = Actor.system("test")
PASSWORD = "correct horse battery staple"
CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
API_KEY = re.compile(r"sdb_live_[A-Za-z0-9]{12}_[A-Za-z0-9]{32}")
TOKEN = re.compile(r"tok_[a-z_]+_[A-Za-z0-9]{22}")
PAN = "ABCDE1234F"


@dataclass
class Console:
    client: TestClient
    db: Database
    tenant: uuid.UUID
    secrets: dict[str, str]
    user_ids: dict[str, uuid.UUID]
    _step: int = 0

    def code(self, email: str) -> str:
        return pyotp.TOTP(self.secrets[email]).at(int(time.time()))

    def csrf(self, path: str) -> str:
        response = self.client.get(path)
        assert response.status_code == 200, (path, response.status_code)
        match = CSRF.search(response.text)
        assert match is not None, f"no CSRF field on {path}"
        return match.group(1)

    def login(self, email: str = "owner@example.com") -> None:
        token = self.csrf("/console/login")
        form = {"tenant": "acme", "email": email, "password": PASSWORD, "csrf_token": token}
        response = self.client.post("/console/login", data=form)
        assert response.status_code == 303, response.text
        assert response.headers["location"] == "/console/login/totp"
        token = self.csrf("/console/login/totp")
        response = self.client.post(
            "/console/login/totp", data={"code": self.code(email), "csrf_token": token}
        )
        assert response.status_code == 303, response.text
        assert response.headers["location"] == "/console"

    def post(self, path: str, page: str, **form: object):  # type: ignore[no-untyped-def]
        return self.client.post(path, data={"csrf_token": self.csrf(page), **form})

    def audit(self) -> list[AuditRecord]:
        with self.db.tenant_session(self.tenant) as session:
            return list_entries(session, self.tenant, limit=200)


@pytest.fixture
def console(
    settings: Settings, key_provider: LocalKeyProvider, clean_db: None
) -> Iterator[Console]:
    app = create_app(settings, Database(settings.database_url), key_provider)
    db: Database = app.state.db
    tenant = create_tenant(db, app.state.keyring, "acme", actor=TEST)
    secrets: dict[str, str] = {}
    user_ids: dict[str, uuid.UUID] = {}
    for email, role in (("owner@example.com", "owner"), ("viewer@example.com", "viewer")):
        with db.tenant_session(tenant) as session:
            user_id, uri = auth.create_console_user(
                session, app.state.keyring, tenant, email, PASSWORD, role, actor=TEST
            )
        secrets[email] = parse_qs(urlparse(uri).query)["secret"][0]
        user_ids[email] = user_id
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    yield Console(client, db, tenant, secrets, user_ids)
    db.dispose()


def _create_key(console: Console, name: str = "billing", *scopes: str) -> str:
    response = console.post(
        "/console/keys",
        "/console/keys",
        name=name,
        scopes=list(scopes or ("tokenize", "detokenize")),
    )
    assert response.status_code == 200, response.text
    match = API_KEY.search(response.text)
    assert match is not None
    return match.group(0)


def _key_id(console: Console, plaintext: str) -> uuid.UUID:
    with console.db.tenant_session(console.tenant) as session:
        key_id = session.scalar(select(ApiKey.id).where(ApiKey.prefix == plaintext.split("_")[2]))
    assert key_id is not None
    return key_id


def _allow(console: Console, key_id: uuid.UUID, field_type: str, action: str, effect: str) -> None:
    response = console.post(
        f"/console/keys/{key_id}/policy", "/console/keys",
        field_type=field_type, action=action, effect=effect,
    )  # fmt: skip
    assert response.status_code == 303, response.text


# --- Login ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/console", "/console/keys", "/console/audit", "/console/encryption", "/console/playground"],
)
def test_pages_require_login(console: Console, path: str) -> None:
    response = console.client.get(path)
    assert response.status_code == 303
    assert response.headers["location"] == "/console/login"


def test_login_with_password_and_totp(console: Console) -> None:
    console.login()
    page = console.client.get("/console")
    assert page.status_code == 200
    assert "owner@example.com" in page.text and "acme" in page.text


@pytest.mark.parametrize(
    ("tenant", "email", "password"),
    [
        ("acme", "owner@example.com", "the wrong password"),
        ("acme", "nobody@example.com", PASSWORD),
        ("nowhere", "owner@example.com", PASSWORD),
    ],
)
def test_failed_logins_get_one_generic_message(
    console: Console, tenant: str, email: str, password: str
) -> None:
    token = console.csrf("/console/login")
    response = console.client.post(
        "/console/login",
        data={"tenant": tenant, "email": email, "password": password, "csrf_token": token},
    )
    assert response.status_code == 401
    assert "Invalid tenant, e-mail or password." in response.text
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


def test_password_alone_does_not_open_the_console(console: Console) -> None:
    token = console.csrf("/console/login")
    form = {
        "tenant": "acme",
        "email": "owner@example.com",
        "password": PASSWORD,
        "csrf_token": token,
    }
    assert console.client.post("/console/login", data=form).status_code == 303
    assert console.client.get("/console").headers["location"] == "/console/login"
    token = console.csrf("/console/login/totp")
    wrong = console.client.post("/console/login/totp", data={"code": "000000", "csrf_token": token})
    assert wrong.status_code == 401
    assert console.client.get("/console").status_code == 303


def test_login_forms_require_the_csrf_token(console: Console) -> None:
    console.client.get("/console/login")
    form = {"tenant": "acme", "email": "owner@example.com", "password": PASSWORD}
    assert console.client.post("/console/login", data=form).status_code == 403
    bad = console.client.post("/console/login", data={**form, "csrf_token": "forged"})
    assert bad.status_code == 403


def test_session_cookie_is_hardened_and_rotates_after_totp(console: Console) -> None:
    token = console.csrf("/console/login")
    form = {
        "tenant": "acme",
        "email": "owner@example.com",
        "password": PASSWORD,
        "csrf_token": token,
    }
    first = console.client.post("/console/login", data=form)
    cookie = first.headers["set-cookie"]
    assert SESSION_COOKIE.startswith("__Host-") and PRE_LOGIN_COOKIE.startswith("__Host-")
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attribute in cookie
    pending = console.client.cookies.get(SESSION_COOKIE)
    token = console.csrf("/console/login/totp")
    console.client.post(
        "/console/login/totp",
        data={"code": console.code("owner@example.com"), "csrf_token": token},
    )
    verified = console.client.cookies.get(SESSION_COOKIE)
    assert pending and verified and pending != verified
    assert auth.load_session(console.db, pending) is None  # the pending session is gone


def test_logout(console: Console) -> None:
    console.login()
    assert console.client.post("/console/logout").status_code == 403  # needs CSRF
    assert console.client.get("/console").status_code == 200
    response = console.post("/console/logout", "/console")
    assert response.status_code == 303
    assert console.client.get("/console").status_code == 303


# --- Keys and policies -----------------------------------------------------------


def test_owner_creates_a_key_shown_once(console: Console) -> None:
    console.login()
    plaintext = _create_key(console)
    assert authenticate(console.db, f"Bearer {plaintext}").scopes == frozenset(
        {"tokenize", "detokenize"}
    )
    listing = console.client.get("/console/keys").text
    assert plaintext.split("_")[2] in listing  # prefix is listed
    assert plaintext not in listing  # the secret is never shown again
    entry = console.audit()[-1]
    assert (entry.action, entry.actor_type) == ("api_key.create", "console_user")
    assert entry.actor_id == str(console.user_ids["owner@example.com"])


@pytest.mark.parametrize("token", [None, "forged-token"])
def test_state_changes_need_a_valid_csrf_token(console: Console, token: str | None) -> None:
    console.login()
    form: dict[str, object] = {"name": "billing", "scopes": ["tokenize"]}
    if token is not None:
        form["csrf_token"] = token
    assert console.client.post("/console/keys", data=form).status_code == 403
    with console.db.tenant_session(console.tenant) as session:
        assert session.scalars(select(ApiKey)).all() == []


def test_names_are_escaped_in_pages(console: Console) -> None:
    console.login()
    _create_key(console, "<script>alert(1)</script>")
    page = console.client.get("/console/keys").text
    assert "<script" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_set_policy_and_revoke(console: Console) -> None:
    console.login()
    plaintext = _create_key(console)
    key_id = _key_id(console, plaintext)
    _allow(console, key_id, "pan", "detokenize", "mask")
    assert "mask" in console.client.get("/console/keys").text
    response = console.post(f"/console/keys/{key_id}/revoke", "/console/keys")
    assert response.status_code == 303
    assert "revoked" in console.client.get("/console/keys").text.lower()
    assert [e.action for e in console.audit()[-2:]] == ["policy.set", "api_key.revoke"]


def test_viewer_is_read_only(console: Console) -> None:
    console.login("viewer@example.com")
    for path in ("/console", "/console/keys", "/console/audit", "/console/encryption"):
        assert console.client.get(path).status_code == 200, path
    assert console.client.get("/console/playground").status_code == 403
    token = console.csrf("/console/keys")
    for path, form in (
        ("/console/keys", {"name": "x", "scopes": ["tokenize"]}),
        ("/console/encryption/rotate", {}),
        ("/console/encryption/reencrypt", {}),
        (
            "/console/playground/tokenize",
            {"key_id": str(uuid.uuid4()), "type": "pan", "value": PAN},
        ),
    ):
        response = console.client.post(path, data={"csrf_token": token, **form})
        assert response.status_code == 403, path
    with console.db.tenant_session(console.tenant) as session:
        assert session.scalars(select(ApiKey)).all() == []


# --- Audit, encryption, playground ---------------------------------------------


def test_audit_page_and_verification(console: Console) -> None:
    console.login()
    page = console.client.get("/console/audit")
    assert page.status_code == 200
    assert "tenant.create" in page.text and "console.login" in page.text
    verify = console.client.get("/console/audit/verify")
    assert verify.status_code == 200 and "intact" in verify.text.lower()
    bad = console.client.get(
        "/console/audit/verify", params={"anchor_seq": 1, "anchor_hash": "0" * 64}
    )
    assert "broken" in bad.text.lower()


def test_rotate_and_reencrypt_from_the_console(console: Console) -> None:
    console.login()
    plaintext = _create_key(console)
    key_id = _key_id(console, plaintext)
    _allow(console, key_id, "pan", "tokenize", "allow")
    console.post(
        "/console/playground/tokenize",
        "/console/playground",
        key_id=str(key_id),
        type="pan",
        value=PAN,
    )
    assert console.post("/console/encryption/rotate", "/console/encryption").status_code == 303
    assert console.post("/console/encryption/reencrypt", "/console/encryption").status_code == 303
    with console.db.tenant_session(console.tenant) as session:
        statuses = dict(session.execute(select(TenantKey.version, TenantKey.status)).all())
        assert session.scalars(select(Token.key_version)).all() == [2]
    assert statuses == {1: "retired", 2: "active"}
    rotation = [e for e in console.audit() if e.action.startswith("key.")]
    assert rotation and all(e.actor_type == "console_user" for e in rotation)
    page = console.client.get("/console/encryption").text
    assert "retired" in page and "active" in page


def test_playground_uses_the_selected_keys_policies(console: Console) -> None:
    console.login()
    plaintext = _create_key(console)
    key_id = _key_id(console, plaintext)
    denied = console.post(
        "/console/playground/tokenize",
        "/console/playground",
        key_id=str(key_id),
        type="pan",
        value=PAN,
    )
    assert denied.status_code == 200 and "may not tokenize" in denied.text
    _allow(console, key_id, "pan", "tokenize", "allow")
    _allow(console, key_id, "pan", "detokenize", "mask")
    made = console.post(
        "/console/playground/tokenize",
        "/console/playground",
        key_id=str(key_id),
        type="pan",
        value=PAN,
    )
    match = TOKEN.search(made.text)
    assert made.status_code == 200 and match is not None
    assert PAN not in made.text
    shown = console.post(
        "/console/playground/detokenize", "/console/playground",
        key_id=str(key_id), token=match.group(0),
    )  # fmt: skip
    assert "XXXXXX234F" in shown.text and PAN not in shown.text
    rejected, tokenize, detokenize = (
        e for e in console.audit() if e.action in ("tokenize.rejected", "tokenize", "detokenize")
    )
    for entry in (rejected, tokenize, detokenize):
        assert entry.actor_type == "console_user"
        assert entry.outcome["via_key"] == str(key_id)


def test_playground_reports_invalid_values_without_echoing_them(console: Console) -> None:
    console.login()
    key_id = _key_id(console, _create_key(console))
    _allow(console, key_id, "pan", "tokenize", "allow")
    response = console.post(
        "/console/playground/tokenize", "/console/playground",
        key_id=str(key_id), type="pan", value="NOTAPAN99",
    )  # fmt: skip
    assert response.status_code == 200 and "Invalid PAN" in response.text
    assert "NOTAPAN99" not in response.text


# --- Headers ---------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/console/login", "/healthz", "/v1/audit", "/no-such-page"])
def test_security_headers_on_every_response(console: Console, path: str) -> None:
    headers = console.client.get(path).headers
    assert headers["content-security-policy"].startswith("default-src 'none'")
    assert "script-src" not in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert "max-age=" in headers["strict-transport-security"]


def test_console_uses_no_scripts_or_inline_styles(console: Console) -> None:
    console.login("owner@example.com")
    for path in (
        "/console",
        "/console/keys",
        "/console/audit",
        "/console/encryption",
        "/console/playground",
    ):
        page = console.client.get(path).text
        assert "<script" not in page and "style=" not in page and "onclick" not in page, path
    css = console.client.get("/console/static/console.css")
    assert css.status_code == 200 and css.headers["content-type"].startswith("text/css")


def test_login_attempts_are_throttled(console: Console) -> None:
    token = console.csrf("/console/login")
    form = {
        "tenant": "acme",
        "email": "owner@example.com",
        "password": "nope nope nope",
        "csrf_token": token,
    }
    statuses = [console.client.post("/console/login", data=form).status_code for _ in range(12)]
    assert statuses[:4] == [401] * 4
    assert statuses[-1] == 429


def test_owner_can_edit_a_keys_scopes(console: Console) -> None:
    console.login()
    plaintext = _create_key(console)
    key_id = _key_id(console, plaintext)
    response = console.post(
        f"/console/keys/{key_id}/scopes", "/console/keys", scopes=["audit:read"]
    )
    assert response.status_code == 303
    assert authenticate(console.db, f"Bearer {plaintext}").scopes == frozenset({"audit:read"})
    entry = console.audit()[-1]
    assert (entry.action, entry.actor_type) == ("api_key.update_scopes", "console_user")
    assert entry.outcome == {"key_id": str(key_id), "scopes": ["audit:read"]}
    empty = console.post(f"/console/keys/{key_id}/scopes", "/console/keys")
    assert empty.status_code == 200 and "at least one scope" in empty.text


def test_playground_respects_the_keys_scopes(console: Console) -> None:
    console.login()
    key_id = _key_id(console, _create_key(console, "tokenize-only", "tokenize"))
    _allow(console, key_id, "pan", "tokenize", "allow")
    _allow(console, key_id, "pan", "detokenize", "allow")
    made = console.post(
        "/console/playground/tokenize",
        "/console/playground",
        key_id=str(key_id),
        type="pan",
        value=PAN,
    )
    match = TOKEN.search(made.text)
    assert match is not None
    shown = console.post(
        "/console/playground/detokenize", "/console/playground",
        key_id=str(key_id), token=match.group(0),
    )  # fmt: skip
    assert "lacks the &#39;detokenize&#39; scope" in shown.text
    assert PAN not in shown.text
    last = console.audit()[-1]
    assert (last.action, last.outcome["reason"]) == ("detokenize.rejected", "scope")


def test_non_ascii_csrf_token_is_a_403(console: Console) -> None:
    console.login()
    response = console.client.post("/console/keys", data={"name": "x", "csrf_token": "١٢٣"})
    assert response.status_code == 403
