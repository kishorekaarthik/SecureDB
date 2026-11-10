import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import select

from securedb.audit.log import Actor, list_entries
from securedb.crypto.local import LocalKeyProvider
from securedb.crypto.tenant_keys import KeyRing
from securedb.db.models import Token, TokenSubject
from securedb.db.session import Database
from securedb.policy.engine import Action, Effect, set_policy
from securedb.tenants.api_keys import AuthenticatedKey, Scope, issue_api_key
from securedb.tenants.service import create_tenant
from securedb.vault.fields import FieldType
from securedb.vault.service import NOT_AVAILABLE, TokenizeItem, TokenService
from securedb.vault.subjects import SubjectService

TEST = Actor.system("test")
PAN = "ABCDE1234F"


@dataclass
class World:
    db: Database
    tokens: TokenService
    subjects: SubjectService
    tenant: uuid.UUID
    key: AuthenticatedKey


def _key(db: Database, tenant: uuid.UUID, effects: dict[FieldType, Effect]) -> AuthenticatedKey:
    with db.tenant_session(tenant) as session:
        issued = issue_api_key(session, tenant, "svc", [Scope.tokenize], actor=TEST)
        for field_type in FieldType:
            set_policy(
                session, tenant, issued.id, field_type, Action.tokenize, Effect.allow, actor=TEST
            )
        for field_type, effect in effects.items():
            set_policy(
                session, tenant, issued.id, field_type, Action.detokenize, effect, actor=TEST
            )
    return AuthenticatedKey(issued.id, tenant, frozenset({"tokenize", "detokenize"}))


@pytest.fixture
def world(db: Database, key_provider: LocalKeyProvider) -> World:
    keyring = KeyRing(key_provider)
    tenant = create_tenant(db, keyring, "acme", actor=TEST)
    key = _key(db, tenant, {FieldType.pan: Effect.allow, FieldType.email: Effect.mask})
    return World(db, TokenService(keyring), SubjectService(keyring), tenant, key)


def _tokenize(w: World, field_type: FieldType, value: str, subject: str | None) -> str:
    with w.db.tenant_session(w.tenant) as session:
        [result] = w.tokens.tokenize(session, w.key, [TokenizeItem(field_type, value, subject)])
    return result.token


def _exists(w: World, token: str) -> bool:
    with w.db.tenant_session(w.tenant) as session:
        return session.get(Token, token) is not None


def test_erasure_deletes_tokens_owned_only_by_the_subject(world: World) -> None:
    pan = _tokenize(world, FieldType.pan, PAN, "alice")
    shared = _tokenize(world, FieldType.email, "family@example.com", "alice")
    _tokenize(world, FieldType.email, "family@example.com", "bob")
    other = _tokenize(world, FieldType.email, "bob@example.com", "bob")

    with world.db.tenant_session(world.tenant) as session:
        result = world.subjects.erase(session, world.key, "alice")
    assert result.deleted_tokens == [pan]
    assert result.retained_shared == 1
    assert not _exists(world, pan)
    assert _exists(world, shared) and _exists(world, other)
    with world.db.tenant_session(world.tenant) as session:
        assert session.scalars(
            select(TokenSubject.subject_id).where(TokenSubject.token == shared)
        ).all() == ["bob"]
        [detok] = world.tokens.detokenize(session, world.key, [pan])
    assert detok.error == NOT_AVAILABLE


def test_erasing_the_last_owner_deletes_a_shared_token(world: World) -> None:
    shared = _tokenize(world, FieldType.email, "family@example.com", "alice")
    _tokenize(world, FieldType.email, "family@example.com", "bob")
    for subject in ("alice", "bob"):
        with world.db.tenant_session(world.tenant) as session:
            world.subjects.erase(session, world.key, subject)
    assert not _exists(world, shared)


def test_erasure_is_audited_with_a_keyed_reference_not_the_subject_id(world: World) -> None:
    pan = _tokenize(world, FieldType.pan, PAN, "alice-ssn-like-id")
    with world.db.tenant_session(world.tenant) as session:
        world.subjects.erase(session, world.key, "alice-ssn-like-id")
        entry = list_entries(session, world.tenant, limit=200)[-1]
        again = world.subjects.subject_ref(session, world.tenant, "alice-ssn-like-id")
    assert entry.action == "subject.erase"
    assert entry.token_ids == [pan]
    assert entry.outcome == {"subject_ref": again, "deleted": 1, "retained_shared": 0}
    assert len(again) == 64
    assert "alice" not in json.dumps(entry.outcome) and PAN not in json.dumps(entry.outcome)


def test_erasing_an_unknown_subject_is_a_no_op(world: World) -> None:
    with world.db.tenant_session(world.tenant) as session:
        result = world.subjects.erase(session, world.key, "nobody")
    assert (result.deleted_tokens, result.retained_shared) == ([], 0)


def test_export_lists_tokens_values_by_policy_and_history(world: World) -> None:
    pan = _tokenize(world, FieldType.pan, PAN, "alice")
    email = _tokenize(world, FieldType.email, "family@example.com", "alice")
    _tokenize(world, FieldType.email, "family@example.com", "bob")
    phone = _tokenize(world, FieldType.phone, "9876543210", "alice")
    with world.db.tenant_session(world.tenant) as session:
        world.tokens.detokenize(session, world.key, [pan])
    with world.db.tenant_session(world.tenant) as session:
        export = world.subjects.export(session, world.key, "alice")

    by_token = {t.token: t for t in export.tokens}
    assert set(by_token) == {pan, email, phone}
    assert (by_token[pan].value, by_token[pan].masked, by_token[pan].shared) == (PAN, False, False)
    assert (by_token[email].value, by_token[email].masked) == ("f***@example.com", True)
    assert by_token[email].shared is True
    assert by_token[phone].value is None  # no detokenize policy for phone
    assert by_token[pan].type == "pan" and by_token[pan].created_at is not None
    actions = [h.action for h in export.history]
    assert actions.count("tokenize") == 4 and "detokenize" in actions
    with world.db.tenant_session(world.tenant) as session:
        assert export.subject_ref == world.subjects.subject_ref(session, world.tenant, "alice")


def test_export_is_audited(world: World) -> None:
    pan = _tokenize(world, FieldType.pan, PAN, "alice")
    with world.db.tenant_session(world.tenant) as session:
        world.subjects.export(session, world.key, "alice")
        entry = list_entries(session, world.tenant, limit=200)[-1]
    assert entry.action == "subject.export"
    assert entry.token_ids == [pan]
    assert entry.outcome["tokens"] == 1 and len(entry.outcome["subject_ref"]) == 64


def test_subjects_are_isolated_between_tenants(
    world: World, key_provider: LocalKeyProvider
) -> None:
    _tokenize(world, FieldType.pan, PAN, "alice")
    keyring = KeyRing(key_provider)
    other = create_tenant(world.db, keyring, "globex", actor=TEST)
    other_key = _key(world.db, other, {FieldType.pan: Effect.allow})
    service = SubjectService(keyring)
    with world.db.tenant_session(other) as session:
        assert service.export(session, other_key, "alice").tokens == []
        assert service.erase(session, other_key, "alice").deleted_tokens == []
    with world.db.tenant_session(world.tenant) as session:
        assert world.subjects.export(session, world.key, "alice").tokens != []


def test_tokenize_racing_an_erasure_never_fails_or_returns_a_dead_token(world: World) -> None:
    import threading

    errors: list[BaseException] = []
    for round_number in range(20):
        value = f"race{round_number}@example.com"
        _tokenize(world, FieldType.email, value, "alice")
        barrier = threading.Barrier(2)
        carol_token: list[str] = []

        def erase_alice(barrier: threading.Barrier = barrier) -> None:
            try:
                barrier.wait()
                with world.db.tenant_session(world.tenant) as session:
                    world.subjects.erase(session, world.key, "alice")
            except BaseException as exc:  # collected for the assertion below
                errors.append(exc)

        def tokenize_carol(
            barrier: threading.Barrier = barrier,
            value: str = value,
            out: list[str] = carol_token,
        ) -> None:
            try:
                barrier.wait()
                out.append(_tokenize(world, FieldType.email, value, "carol"))
            except BaseException as exc:  # collected for the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=erase_alice), threading.Thread(target=tokenize_carol)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        [token] = carol_token
        assert _exists(world, token), f"round {round_number}: carol got a deleted token"
        with world.db.tenant_session(world.tenant) as session:
            [detok] = world.tokens.detokenize(session, world.key, [token])
        assert detok.error is None
