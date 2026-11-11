"""Demo data: two tenants with sample (fake) PII, API keys with different policies and a
console owner each. Shows masking per key and isolation between tenants."""

import uuid
from dataclasses import dataclass, field

from securedb.audit.log import Actor
from securedb.console.auth import create_console_user
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.session import Database
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import AuthenticatedKey, Scope, issue_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType, verhoeff_check_digit
from securedb.vault.service import TokenizeItem, TokenService

DEMO_TENANTS = ("acme-lending", "globex-hr")
ACTOR = Actor.system("seed-demo")
_TYPES = (
    FieldType.pan,
    FieldType.aadhaar,
    FieldType.bank_account,
    FieldType.phone,
    FieldType.email,
)


@dataclass(frozen=True)
class DemoTenant:
    id: uuid.UUID
    name: str
    console_email: str
    totp_uri: str = field(repr=False)
    backend_key: str = field(repr=False)
    support_key: str = field(repr=False)
    sample_tokens: list[str]


@dataclass(frozen=True)
class DemoResult:
    tenants: list[DemoTenant]


def _aadhaar(base: str) -> str:
    return base + verhoeff_check_digit(base)


def _customers(index: int) -> list[tuple[str, list[TokenizeItem]]]:
    """Two made-up customers per tenant. None of these values belong to real people."""
    n = index + 1
    return [
        (
            f"cust-{n}001",
            [
                TokenizeItem(FieldType.pan, f"ABCPD{n}234K"),
                TokenizeItem(FieldType.aadhaar, _aadhaar(f"2345{n}678901")),
                TokenizeItem(
                    FieldType.bank_account,
                    {"account_number": f"5010{n}0123456", "ifsc": "HDFC0001234"},
                ),
                TokenizeItem(FieldType.phone, f"98765{n}3210"),
                TokenizeItem(FieldType.email, f"asha.rao{n}@example.com"),
            ],
        ),
        (
            f"cust-{n}002",
            [
                TokenizeItem(FieldType.pan, f"XYZPM{n}876L"),
                TokenizeItem(FieldType.phone, f"91234{n}6780"),
                TokenizeItem(FieldType.email, f"vikram.shah{n}@example.com"),
            ],
        ),
    ]


def seed_demo(db: Database, keyring: KeyRing, console_password: str) -> DemoResult:
    """Create the demo tenants. Raises Conflict if they already exist."""
    service = TokenService(keyring)
    tenants: list[DemoTenant] = []
    for index, name in enumerate(DEMO_TENANTS):
        tenant_id = create_tenant(db, keyring, name, actor=ACTOR)
        email = f"owner@{name}.example"
        with db.tenant_session(tenant_id) as session:
            _user, totp_uri = create_console_user(
                session, keyring, tenant_id, email, console_password, "owner", actor=ACTOR
            )
            backend = issue_api_key(session, tenant_id, "backend", list(Scope), actor=ACTOR)
            support = issue_api_key(session, tenant_id, "support", [Scope.detokenize], actor=ACTOR)
            for field_type in _TYPES:
                for key, action, effect in (
                    (backend, Action.tokenize, Effect.allow),
                    (backend, Action.detokenize, Effect.allow),
                    (support, Action.detokenize, Effect.mask),
                ):
                    set_policy(session, tenant_id, key.id, field_type, action, effect, actor=ACTOR)
        acting = AuthenticatedKey(backend.id, tenant_id, frozenset(s.value for s in Scope))
        sample: list[str] = []
        for subject, items in _customers(index):
            with db.tenant_session(tenant_id) as session:
                results = service.tokenize(
                    session,
                    acting,
                    [TokenizeItem(i.type, i.value, subject) for i in items],
                )
            sample.extend(result.token for result in results)
        tenants.append(
            DemoTenant(
                id=tenant_id,
                name=name,
                console_email=email,
                totp_uri=totp_uri,
                backend_key=backend.plaintext,
                support_key=support.plaintext,
                sample_tokens=sample,
            )
        )
    return DemoResult(tenants)
