import pytest
from hypothesis import given
from hypothesis import strategies as st

from securedb.vault.fields import (
    FieldType,
    FieldValidationError,
    mask,
    normalize,
    to_output,
    verhoeff_check_digit,
)

VALID_AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")


# --- PAN ---------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["ABCDE1234F", "abcde1234f", " ABCDE 1234F "])
def test_pan_is_normalized_to_uppercase_without_spaces(raw: str) -> None:
    assert normalize(FieldType.pan, raw) == "ABCDE1234F"


@pytest.mark.parametrize("raw", ["", "ABCD1234F", "ABCDE12345", "1BCDE1234F", "ABCDE1234FF"])
def test_invalid_pan_is_rejected(raw: str) -> None:
    with pytest.raises(FieldValidationError, match="PAN"):
        normalize(FieldType.pan, raw)


def test_pan_mask() -> None:
    assert mask(FieldType.pan, "ABCDE1234F") == "XXXXXX234F"


# --- Aadhaar -----------------------------------------------------------------


def test_aadhaar_accepts_spaces_and_hyphens() -> None:
    spaced = f"{VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]}-{VALID_AADHAAR[8:]}"
    assert normalize(FieldType.aadhaar, spaced) == VALID_AADHAAR


def test_aadhaar_with_wrong_checksum_is_rejected() -> None:
    wrong = VALID_AADHAAR[:-1] + str((int(VALID_AADHAAR[-1]) + 1) % 10)
    with pytest.raises(FieldValidationError, match="Aadhaar"):
        normalize(FieldType.aadhaar, wrong)


@pytest.mark.parametrize("raw", ["", "1234", "0" + VALID_AADHAAR[1:], "1" + VALID_AADHAAR[1:]])
def test_malformed_aadhaar_is_rejected(raw: str) -> None:
    with pytest.raises(FieldValidationError, match="Aadhaar"):
        normalize(FieldType.aadhaar, raw)


def test_aadhaar_mask() -> None:
    assert mask(FieldType.aadhaar, VALID_AADHAAR) == "XXXX XXXX " + VALID_AADHAAR[-4:]


@given(st.text(alphabet="0123456789", min_size=11, max_size=11))
def test_verhoeff_check_digit_always_validates(base: str) -> None:
    number = "2" + base[1:] + verhoeff_check_digit("2" + base[1:])
    assert normalize(FieldType.aadhaar, number) == number


# --- Bank account ------------------------------------------------------------


def test_bank_account_is_normalized_to_canonical_json() -> None:
    raw = {"account_number": "1234 5678 9012", "ifsc": "hdfc0001234"}
    normalized = normalize(FieldType.bank_account, raw)
    assert normalized == '{"account_number":"123456789012","ifsc":"HDFC0001234"}'
    assert to_output(FieldType.bank_account, normalized) == {
        "account_number": "123456789012",
        "ifsc": "HDFC0001234",
    }


@pytest.mark.parametrize(
    "raw",
    [
        "123456789012",
        {"account_number": "12345678", "ifsc": "HDFC0001234"},
        {"account_number": "1" * 19, "ifsc": "HDFC0001234"},
        {"account_number": "123456789012", "ifsc": "HDFC1001234"},
        {"account_number": "123456789012"},
        {"account_number": 123456789012, "ifsc": "HDFC0001234"},
    ],
)
def test_invalid_bank_account_is_rejected(raw: object) -> None:
    with pytest.raises(FieldValidationError, match="bank account"):
        normalize(FieldType.bank_account, raw)


def test_bank_account_mask_keeps_ifsc() -> None:
    normalized = normalize(
        FieldType.bank_account, {"account_number": "123456789012", "ifsc": "HDFC0001234"}
    )
    assert mask(FieldType.bank_account, normalized) == {
        "account_number": "XXXXXXXX9012",
        "ifsc": "HDFC0001234",
    }


# --- Phone -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("9876543210", "+919876543210"),
        ("98765 43210", "+919876543210"),
        ("+91 98765-43210", "+919876543210"),
        ("919876543210", "+919876543210"),
        ("+14155552671", "+14155552671"),
    ],
)
def test_phone_is_normalized_to_e164(raw: str, expected: str) -> None:
    assert normalize(FieldType.phone, raw) == expected


@pytest.mark.parametrize("raw", ["", "12345", "5876543210", "+0123456789", "phone"])
def test_invalid_phone_is_rejected(raw: str) -> None:
    with pytest.raises(FieldValidationError, match="phone"):
        normalize(FieldType.phone, raw)


def test_phone_masks() -> None:
    assert mask(FieldType.phone, "+919876543210") == "+91XXXXXX3210"
    assert mask(FieldType.phone, "+14155552671") == "+XXXXXXX2671"


# --- Email -------------------------------------------------------------------


def test_email_is_lowercased_and_trimmed() -> None:
    assert normalize(FieldType.email, "  Priya.S@Example.COM ") == "priya.s@example.com"


@pytest.mark.parametrize("raw", ["", "no-at-sign", "a@b", "a@@b.com", "a b@c.com"])
def test_invalid_email_is_rejected(raw: str) -> None:
    with pytest.raises(FieldValidationError, match="email"):
        normalize(FieldType.email, raw)


def test_email_mask() -> None:
    assert mask(FieldType.email, "priya.s@example.com") == "p***@example.com"


# --- Generic -----------------------------------------------------------------


def test_generic_keeps_value_and_masks_fully() -> None:
    assert normalize(FieldType.generic, " any value ") == " any value "
    assert mask(FieldType.generic, "secret") == "****"


@pytest.mark.parametrize("raw", ["", "x" * 4097])
def test_generic_length_limits(raw: str) -> None:
    with pytest.raises(FieldValidationError, match="generic"):
        normalize(FieldType.generic, raw)


# --- Cross-cutting -----------------------------------------------------------


@pytest.mark.parametrize(
    ("field_type", "raw"),
    [
        (FieldType.pan, "SECRETVALUE123"),
        (FieldType.aadhaar, "999988887777"),
        (FieldType.email, "SECRETVALUE123"),
        (FieldType.phone, "SECRETVALUE123"),
        (FieldType.bank_account, {"account_number": "SECRETVALUE123", "ifsc": "x"}),
    ],
)
def test_validation_errors_never_contain_the_value(field_type: FieldType, raw: object) -> None:
    with pytest.raises(FieldValidationError) as exc_info:
        normalize(field_type, raw)
    assert "SECRETVALUE123" not in str(exc_info.value)
    assert "999988887777" not in str(exc_info.value)


@pytest.mark.parametrize("field_type", [t for t in FieldType if t is not FieldType.bank_account])
def test_string_types_reject_non_strings(field_type: FieldType) -> None:
    with pytest.raises(FieldValidationError):
        normalize(field_type, {"not": "a string"})


@given(st.from_regex(r"[A-Za-z]{5}[0-9]{4}[A-Za-z]", fullmatch=True))
def test_pan_normalization_is_idempotent(raw: str) -> None:
    once = normalize(FieldType.pan, raw)
    assert normalize(FieldType.pan, once) == once
