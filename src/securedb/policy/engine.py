"""Access policies: what each API key may do with each field type. Deny by default."""

import uuid
from enum import StrEnum

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from securedb.audit.log import Actor, append
from securedb.db.models import ApiKey, Policy
from securedb.errors import NotFound
from securedb.vault.fields import FieldType


class Action(StrEnum):
    tokenize = "tokenize"
    detokenize = "detokenize"


class Effect(StrEnum):
    allow = "allow"
    mask = "mask"
    deny = "deny"


def set_policy(
    session: Session,
    tenant_id: uuid.UUID,
    api_key_id: uuid.UUID,
    field_type: FieldType,
    action: Action,
    effect: Effect,
    actor: Actor | None = None,
) -> None:
    """Grant, change or (with Effect.deny) remove a policy. Call in the tenant's session."""
    if session.get(ApiKey, api_key_id) is None:  # RLS hides other tenants' keys
        raise NotFound("API key not found.")
    match_row = (
        Policy.api_key_id == api_key_id,
        Policy.field_type == field_type.value,
        Policy.action == action.value,
    )
    if action is Action.tokenize and effect not in (Effect.allow, Effect.deny):
        raise ValueError("Tokenize policies can only allow.")
    append(
        session,
        tenant_id,
        actor or Actor.system("cli"),
        "policy.set",
        outcome={
            "key_id": str(api_key_id),
            "field_type": field_type.value,
            "action": action.value,
            "effect": effect.value,
        },
    )
    if effect is Effect.deny:
        session.execute(delete(Policy).where(*match_row))
        return
    statement = insert(Policy).values(
        tenant_id=tenant_id,
        api_key_id=api_key_id,
        field_type=field_type.value,
        action=action.value,
        effect=effect.value,
    )
    session.execute(
        statement.on_conflict_do_update(
            constraint="uq_policies_key_type_action", set_={"effect": effect.value}
        )
    )


def effects_for(session: Session, api_key_id: uuid.UUID, action: Action) -> dict[FieldType, Effect]:
    """All configured effects for one key and action. Missing types mean deny."""
    rows = session.execute(
        select(Policy.field_type, Policy.effect).where(
            Policy.api_key_id == api_key_id, Policy.action == action.value
        )
    ).all()
    return {FieldType(row.field_type): Effect(row.effect) for row in rows}


def decide(
    session: Session, api_key_id: uuid.UUID, field_type: FieldType, action: Action
) -> Effect:
    return effects_for(session, api_key_id, action).get(field_type, Effect.deny)
