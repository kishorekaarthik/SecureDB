"""PII field types: validation, normalisation and masking (spec §1.3).

Error messages never include the submitted value.
"""

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any


class FieldType(StrEnum):
    pan = "pan"
    aadhaar = "aadhaar"
    bank_account = "bank_account"
    phone = "phone"
    email = "email"
    generic = "generic"


class FieldValidationError(ValueError):
    """The value is not valid for its field type. The message never contains the value."""


Output = str | dict[str, str]

_PAN = re.compile(r"[A-Z]{5}[0-9]{4}[A-Z]")
_AADHAAR = re.compile(r"[2-9][0-9]{11}")
_ACCOUNT = re.compile(r"[0-9]{9,18}")
_IFSC = re.compile(r"[A-Z]{4}0[A-Z0-9]{6}")
_E164 = re.compile(r"\+[1-9][0-9]{7,14}")
_INDIAN_MOBILE = re.compile(r"[6-9][0-9]{9}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_SEPARATORS = re.compile(r"[\s\-()]")
GENERIC_MAX_BYTES = 4096

# Verhoeff checksum tables (used by Aadhaar).
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _verhoeff_valid(number: str) -> bool:
    check = 0
    for i, digit in enumerate(reversed(number)):
        check = _D[check][_P[i % 8][int(digit)]]
    return check == 0


def verhoeff_check_digit(base: str) -> str:
    """The Verhoeff check digit to append to `base` (digits only)."""
    check = 0
    for i, digit in enumerate(reversed(base)):
        check = _D[check][_P[(i + 1) % 8][int(digit)]]
    return str(_INV[check])


def _require_str(raw: Any, label: str) -> str:
    if not isinstance(raw, str):
        raise FieldValidationError(f"Invalid {label}: expected a string.")
    return raw


def _pan(raw: Any) -> str:
    value = re.sub(r"\s", "", _require_str(raw, "PAN")).upper()
    if not _PAN.fullmatch(value):
        raise FieldValidationError("Invalid PAN format.")
    return value


def _aadhaar(raw: Any) -> str:
    value = _SEPARATORS.sub("", _require_str(raw, "Aadhaar number"))
    if not _AADHAAR.fullmatch(value) or not _verhoeff_valid(value):
        raise FieldValidationError("Invalid Aadhaar number.")
    return value


def _bank_account(raw: Any) -> str:
    error = FieldValidationError(
        "Invalid bank account: expected {account_number, ifsc} with a valid IFSC."
    )
    if not isinstance(raw, Mapping):
        raise error
    account, ifsc = raw.get("account_number"), raw.get("ifsc")
    if not isinstance(account, str) or not isinstance(ifsc, str):
        raise error
    account = _SEPARATORS.sub("", account)
    ifsc = ifsc.strip().upper()
    if not _ACCOUNT.fullmatch(account) or not _IFSC.fullmatch(ifsc):
        raise error
    return json.dumps({"account_number": account, "ifsc": ifsc}, separators=(",", ":"))


def _phone(raw: Any) -> str:
    value = _SEPARATORS.sub("", _require_str(raw, "phone number"))
    if _INDIAN_MOBILE.fullmatch(value):
        value = "+91" + value
    elif value.startswith("91") and _INDIAN_MOBILE.fullmatch(value[2:]):
        value = "+" + value
    if not _E164.fullmatch(value):
        raise FieldValidationError("Invalid phone number.")
    return value


def _email(raw: Any) -> str:
    value = _require_str(raw, "email address").strip().lower()
    if len(value) > 254 or not _EMAIL.fullmatch(value):
        raise FieldValidationError("Invalid email address.")
    return value


def _generic(raw: Any) -> str:
    value = _require_str(raw, "generic value")
    if not value or len(value.encode("utf-8")) > GENERIC_MAX_BYTES:
        raise FieldValidationError(
            f"Invalid generic value: must be 1 to {GENERIC_MAX_BYTES} bytes."
        )
    return value


_NORMALIZERS = {
    FieldType.pan: _pan,
    FieldType.aadhaar: _aadhaar,
    FieldType.bank_account: _bank_account,
    FieldType.phone: _phone,
    FieldType.email: _email,
    FieldType.generic: _generic,
}


def normalize(field_type: FieldType, raw: Any) -> str:
    """Validate `raw` and return its canonical string form (what gets encrypted)."""
    return _NORMALIZERS[field_type](raw)


def to_output(field_type: FieldType, normalized: str) -> Output:
    """The API representation of a stored value (objects for bank accounts)."""
    if field_type is FieldType.bank_account:
        parsed: dict[str, str] = json.loads(normalized)
        return parsed
    return normalized


def mask(field_type: FieldType, normalized: str) -> Output:
    """The masked API representation of a stored value (spec §1.3)."""
    match field_type:
        case FieldType.pan:
            return "XXXXXX" + normalized[-4:]
        case FieldType.aadhaar:
            return "XXXX XXXX " + normalized[-4:]
        case FieldType.bank_account:
            account = json.loads(normalized)
            number = account["account_number"]
            return {
                "account_number": "X" * (len(number) - 4) + number[-4:],
                "ifsc": account["ifsc"],
            }
        case FieldType.phone:
            if normalized.startswith("+91"):
                return "+91XXXXXX" + normalized[-4:]
            return "+" + "X" * (len(normalized) - 5) + normalized[-4:]
        case FieldType.email:
            local, domain = normalized.split("@", 1)
            return local[0] + "***@" + domain
        case FieldType.generic:
            return "****"
