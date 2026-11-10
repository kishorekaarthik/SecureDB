import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest
from sqlalchemy import func, select

from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import Token, TokenSubject
from securedb.db.session import Database
from securedb.errors import Forbidden, NotFound, UnprocessableEntity
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import AuthenticatedKey, Scope, issue_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType, verhoeff_check_digit
from securedb.vault.service import NOT_AVAILABLE, TokenizeItem, TokenService

PAN = "ABCDE1234F"
AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")
ACCOUNT = {"account_number": "123456789012", "ifsc": "HDFC0001234"}


@dataclass
class World:
    service: TokenService
    tenant: uuid.UUID
    key: AuthenticatedKey


def _key_with_policies(
    db: Database, tenant: uuid.UUID, policies: dict[tuple[FieldType, Action], Effect]
) -> AuthenticatedKey:
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", [Scope.tokenize, Scope.detokenize])
        for (field_type, action), effect in policies.items():
            set_policy(session, tenant, issued.id, field_type, action, effect)
    return AuthenticatedKey(issued.id, tenant, frozenset({"tokenize", "detokenize"}))


STANDARD_POLICIES = {
    **{(t, Action.tokenize): Effect.allow for t in FieldType if t is not FieldType.phone},
    (FieldType.pan, Action.detokenize): Effect.allow,
    (FieldType.email, Action.detokenize): Effect.mask,
    (FieldType.bank_account, Action.detokenize): Effect.mask,
    (FieldType.generic, Action.detokenize): Effect.allow,
}


@pytest.fixture
def world(db: Database, key_provider: LocalKeyProvider) -> World:
    keyring = KeyRing(key_provider)
    tenant = create_tenant(db, keyring, "acme")
    return World(TokenService(keyring), tenant, _key_with_policies(db, tenant, STANDARD_POLICIES))


def _tokenize(db: Database, w: World, *items: TokenizeItem) -> list[str]:
    with db.tenant_session(w.tenant) as session:
        return [r.token for r in w.service.tokenize(session, w.key, items)]


def _detokenize(db: Database, w: World, *tokens: str, key: AuthenticatedKey | None = None) -> list:
    with db.tenant_session((key or w.key).tenant_id) as session:
        return w.service.detokenize(session, key or w.key, tokens)


def _token_count(db: Database, tenant: uuid.UUID) -> int:
    with db.tenant_session(tenant) as session:
        return session.scalar(select(func.count()).select_from(Token)) or 0


def test_tokenize_returns_opaque_tokens_and_stores_only_ciphertext(
    db: Database, world: World
) -> None:
    with db.tenant_session(world.tenant) as session:
        [result] = world.service.tokenize(session, world.key, [TokenizeItem(FieldType.pan, PAN)])
    assert re.fullmatch(r"tok_pan_[A-Za-z0-9]{22}", result.token)
    assert result.created is True
    with db.tenant_session(world.tenant) as session:
        row = session.get(Token, result.token)
    assert row is not None and PAN.encode() not in row.ciphertext and row.key_version == 1


def test_same_value_returns_the_same_token(db: Database, world: World) -> None:
    first = _tokenize(db, world, TokenizeItem(FieldType.pan, PAN))
    with db.tenant_session(world.tenant) as session:
        second = world.service.tokenize(
            session, world.key, [TokenizeItem(FieldType.pan, " abcde 1234f ")]
        )
    assert second[0].token == first[0]
    assert second[0].created is False
    assert _token_count(db, world.tenant) == 1


def test_detokenize_applies_allow_and_mask(db: Database, world: World) -> None:
    pan, email, account = _tokenize(
        db,
        world,
        TokenizeItem(FieldType.pan, PAN),
        TokenizeItem(FieldType.email, "Priya@Example.com"),
        TokenizeItem(FieldType.bank_account, ACCOUNT),
    )
    results = _detokenize(db, world, pan, email, account)
    assert [(r.value, r.masked, r.error) for r in results] == [
        (PAN, False, None),
        ("p***@example.com", True, None),
        ({"account_number": "XXXXXXXX9012", "ifsc": "HDFC0001234"}, True, None),
    ]


def test_denied_and_unknown_tokens_look_identical(db: Database, world: World) -> None:
    [aadhaar] = _tokenize(db, world, TokenizeItem(FieldType.aadhaar, AADHAAR))
    denied, unknown = _detokenize(db, world, aadhaar, "tok_pan_doesnotexist0000000")
    for result in (denied, unknown):
        assert result.value is None
        assert result.error == NOT_AVAILABLE
        assert result.masked is False


def test_other_tenants_cannot_detokenize(
    db: Database, world: World, key_provider: LocalKeyProvider
) -> None:
    [pan] = _tokenize(db, world, TokenizeItem(FieldType.pan, PAN))
    other_tenant = create_tenant(db, KeyRing(key_provider), "globex")
    other_key = _key_with_policies(db, other_tenant, STANDARD_POLICIES)
    [result] = _detokenize(db, world, pan, key=other_key)
    assert result.error == NOT_AVAILABLE


def test_tokenize_without_policy_is_forbidden_and_writes_nothing(
    db: Database, world: World
) -> None:
    with db.tenant_session(world.tenant) as session, pytest.raises(Forbidden, match="phone"):
        world.service.tokenize(
            session,
            world.key,
            [TokenizeItem(FieldType.pan, PAN), TokenizeItem(FieldType.phone, "9876543210")],
        )
    assert _token_count(db, world.tenant) == 0


def test_invalid_item_rejects_the_whole_batch_without_echoing(db: Database, world: World) -> None:
    with db.tenant_session(world.tenant) as session, pytest.raises(UnprocessableEntity) as exc:
        world.service.tokenize(
            session,
            world.key,
            [TokenizeItem(FieldType.pan, PAN), TokenizeItem(FieldType.pan, "NOTAPAN99")],
        )
    assert "items[1]" in str(exc.value)
    assert "NOTAPAN99" not in str(exc.value)
    assert _token_count(db, world.tenant) == 0


def _subjects(db: Database, w: World, token: str) -> list[str]:
    with db.tenant_session(w.tenant) as session:
        return sorted(
            session.scalars(
                select(TokenSubject.subject_id).where(TokenSubject.token == token)
            ).all()
        )


def test_subject_id_is_recorded(db: Database, world: World) -> None:
    [token] = _tokenize(db, world, TokenizeItem(FieldType.email, "a@b.co", subject_id="cust-42"))
    assert _subjects(db, world, token) == ["cust-42"]


def test_one_value_can_belong_to_several_subjects(db: Database, world: World) -> None:
    phone_like = "family@example.com"
    [first] = _tokenize(db, world, TokenizeItem(FieldType.email, phone_like))
    [second] = _tokenize(db, world, TokenizeItem(FieldType.email, phone_like, subject_id="mum"))
    [third] = _tokenize(db, world, TokenizeItem(FieldType.email, phone_like, subject_id="dad"))
    [again] = _tokenize(db, world, TokenizeItem(FieldType.email, phone_like, subject_id="dad"))
    assert first == second == third == again
    assert _subjects(db, world, first) == ["dad", "mum"]


def test_deleting_a_token_removes_its_subject_links(db: Database, world: World) -> None:
    [token] = _tokenize(db, world, TokenizeItem(FieldType.pan, PAN, subject_id="cust-1"))
    with db.tenant_session(world.tenant) as session:
        world.service.delete_token(session, world.key, token)
    assert _subjects(db, world, token) == []


def test_delete_token(db: Database, world: World) -> None:
    [pan] = _tokenize(db, world, TokenizeItem(FieldType.pan, PAN))
    with db.tenant_session(world.tenant) as session:
        world.service.delete_token(session, world.key, pan)
    assert _detokenize(db, world, pan)[0].error == NOT_AVAILABLE
    with db.tenant_session(world.tenant) as session, pytest.raises(NotFound):
        world.service.delete_token(session, world.key, pan)


def test_concurrent_tokenization_of_one_value_yields_one_token(db: Database, world: World) -> None:
    def tokenize_once(_: int) -> str:
        return _tokenize(db, world, TokenizeItem(FieldType.pan, PAN))[0]

    with ThreadPoolExecutor(max_workers=6) as pool:
        tokens = set(pool.map(tokenize_once, range(12)))
    assert len(tokens) == 1
    assert _token_count(db, world.tenant) == 1


def test_result_reprs_hide_values(db: Database, world: World) -> None:
    [pan] = _tokenize(db, world, TokenizeItem(FieldType.pan, PAN))
    assert PAN not in repr(TokenizeItem(FieldType.pan, PAN))
    assert PAN not in repr(_detokenize(db, world, pan)[0])


def test_opposite_order_batches_do_not_deadlock(db: Database, world: World) -> None:
    import threading

    errors: list[BaseException] = []
    for round_number in range(25):
        x = TokenizeItem(FieldType.email, f"x{round_number}@example.com")
        y = TokenizeItem(FieldType.email, f"y{round_number}@example.com")
        barrier = threading.Barrier(2)

        def run(items: tuple[TokenizeItem, ...], barrier: threading.Barrier = barrier) -> None:
            try:
                barrier.wait()
                _tokenize(db, world, *items)
            except BaseException as exc:  # collected for the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=run, args=(o,)) for o in ((x, y), (y, x))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert errors == []
