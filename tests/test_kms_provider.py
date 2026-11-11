import secrets
from typing import Any

import pytest

from securedb.config import Settings
from securedb.crypto import master_key as mk
from securedb.crypto.kms import AwsKmsKeyProvider, KmsUnavailable
from securedb.crypto.local import LockedKeyProvider
from securedb.crypto.provider import KeyProvider
from securedb.errors import CryptoError, KeyProviderLocked

KEY_ARN = "arn:aws:kms:ap-south-1:111122223333:key/demo"
CONTEXT = {"purpose": "dek", "tenant_id": "t1", "version": "1"}


class FakeKmsError(Exception):
    """Stands in for botocore's ClientError (which carries the AWS error code)."""

    def __init__(self, code: str) -> None:
        super().__init__(f"{code}: secret detail")
        self.response = {"Error": {"Code": code, "Message": "secret detail"}}


class FakeKms:
    """Minimal in-memory KMS: 'encrypts' by remembering (key, context, plaintext)."""

    def __init__(self) -> None:
        self.blobs: dict[bytes, tuple[str, dict[str, str], bytes]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.down = False
        self.enabled = True

    def encrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("encrypt", kwargs))
        if self.down:
            raise FakeKmsError("ThrottlingException")
        blob = secrets.token_bytes(48)
        self.blobs[blob] = (kwargs["KeyId"], dict(kwargs["EncryptionContext"]), kwargs["Plaintext"])
        return {"CiphertextBlob": blob}

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("decrypt", kwargs))
        entry = self.blobs.get(kwargs["CiphertextBlob"])
        if self.down:
            raise FakeKmsError("ThrottlingException")
        if (
            entry is None
            or entry[0] != kwargs["KeyId"]
            or entry[1] != dict(kwargs["EncryptionContext"])
        ):
            raise FakeKmsError("InvalidCiphertextException")
        return {"Plaintext": entry[2]}

    def describe_key(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("describe_key", kwargs))
        if self.down:
            raise FakeKmsError("ThrottlingException")
        return {"KeyMetadata": {"Enabled": self.enabled}}


@pytest.fixture
def kms() -> FakeKms:
    return FakeKms()


@pytest.fixture
def provider(kms: FakeKms) -> AwsKmsKeyProvider:
    return AwsKmsKeyProvider(KEY_ARN, client=kms)


def test_satisfies_the_key_provider_protocol(provider: AwsKmsKeyProvider) -> None:
    assert isinstance(provider, KeyProvider)
    assert (provider.name, provider.key_id) == ("aws-kms", KEY_ARN)
    assert provider.is_unlocked() is True


def test_wrap_round_trip_sends_the_context_to_kms(
    provider: AwsKmsKeyProvider, kms: FakeKms
) -> None:
    dek = secrets.token_bytes(32)
    wrapped = provider.wrap(dek, CONTEXT)
    assert dek not in wrapped
    assert provider.unwrap(wrapped, CONTEXT) == dek
    assert [name for name, _ in kms.calls] == ["encrypt", "decrypt"]
    for _name, kwargs in kms.calls:
        assert kwargs["KeyId"] == KEY_ARN
        assert kwargs["EncryptionContext"] == CONTEXT


def test_unwrap_with_a_different_context_fails(provider: AwsKmsKeyProvider) -> None:
    wrapped = provider.wrap(secrets.token_bytes(32), CONTEXT)
    with pytest.raises(CryptoError):
        provider.unwrap(wrapped, {**CONTEXT, "tenant_id": "t2"})


def test_unwrap_under_a_different_kms_key_fails(provider: AwsKmsKeyProvider, kms: FakeKms) -> None:
    wrapped = provider.wrap(secrets.token_bytes(32), CONTEXT)
    other = AwsKmsKeyProvider("arn:aws:kms:ap-south-1:111122223333:key/other", client=kms)
    with pytest.raises(CryptoError):
        other.unwrap(wrapped, CONTEXT)


def test_kms_errors_become_generic_crypto_errors(provider: AwsKmsKeyProvider, kms: FakeKms) -> None:
    with pytest.raises(CryptoError) as exc_info:
        provider.unwrap(b"garbage", CONTEXT)
    assert exc_info.value.__cause__ is None
    assert "secret detail" not in str(exc_info.value)


def test_is_unlocked_reflects_kms_reachability(provider: AwsKmsKeyProvider, kms: FakeKms) -> None:
    kms.down = True
    assert provider.is_unlocked() is False


def test_repr_shows_only_the_key_id(provider: AwsKmsKeyProvider) -> None:
    assert repr(provider) == f"AwsKmsKeyProvider(key_id={KEY_ARN!r})"


def _settings(**overrides: object) -> Settings:
    url = "postgresql+psycopg://u:p@localhost/x_test"
    return Settings(_env_file=None, database_url=url, migration_database_url=url, **overrides)


def test_kms_store_without_a_key_id_gives_a_locked_provider() -> None:
    provider = mk.load_key_provider(_settings(master_key_store="kms"))
    assert isinstance(provider, LockedKeyProvider)
    assert "SECUREDB_KMS_KEY_ID" in provider.reason


def test_kms_store_builds_the_kms_provider(monkeypatch: pytest.MonkeyPatch, kms: FakeKms) -> None:
    monkeypatch.setattr("securedb.crypto.kms.default_client", lambda region: kms)
    provider = mk.load_key_provider(_settings(master_key_store="kms", kms_key_id=KEY_ARN))
    assert isinstance(provider, AwsKmsKeyProvider)
    assert provider.key_id == KEY_ARN


def test_kms_store_without_boto3_gives_a_locked_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_boto(region: str | None) -> Any:
        raise KmsUnavailable("AWS KMS support needs boto3: install securedb[kms].")

    monkeypatch.setattr("securedb.crypto.kms.default_client", no_boto)
    provider = mk.load_key_provider(_settings(master_key_store="kms", kms_key_id=KEY_ARN))
    assert isinstance(provider, LockedKeyProvider)
    assert "boto3" in provider.reason


def test_an_outage_is_unavailable_not_tampering(
    provider: AwsKmsKeyProvider, kms: FakeKms, capsys: pytest.CaptureFixture[str]
) -> None:
    from securedb.logs import configure_logging

    configure_logging("INFO")
    wrapped = provider.wrap(secrets.token_bytes(32), CONTEXT)
    kms.down = True
    with pytest.raises(KeyProviderLocked):
        provider.unwrap(wrapped, CONTEXT)
    with pytest.raises(KeyProviderLocked):
        provider.wrap(secrets.token_bytes(32), CONTEXT)
    logs = capsys.readouterr().out
    assert "kms_error" in logs and "ThrottlingException" in logs
    assert "secret detail" not in logs


def test_readiness_is_cached(kms: FakeKms) -> None:
    now = [1000.0]
    provider = AwsKmsKeyProvider(KEY_ARN, client=kms, clock=lambda: now[0])
    assert [provider.is_unlocked() for _ in range(5)] == [True] * 5
    assert [name for name, _ in kms.calls].count("describe_key") == 1
    now[0] += 31
    kms.enabled = False
    assert provider.is_unlocked() is False
    assert [name for name, _ in kms.calls].count("describe_key") == 2
