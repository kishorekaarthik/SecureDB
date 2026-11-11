"""AWS KMS key provider: the master key never leaves KMS.

Tenant keys are wrapped with ``kms:Encrypt`` and unwrapped with ``kms:Decrypt``; the wrap
context (purpose, tenant, version) is sent as the KMS *encryption context*, so KMS itself
refuses to unwrap a key for the wrong tenant, and every use shows up in CloudTrail.

boto3 is an optional dependency (``pip install securedb[kms]``).
"""

from collections.abc import Mapping
from typing import Any

from securedb.errors import CryptoError


class KmsUnavailable(Exception):
    """boto3 is not installed or a client could not be created."""


def default_client(region: str | None) -> Any:
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError:
        raise KmsUnavailable("AWS KMS support needs boto3: install securedb[kms].") from None
    return boto3.client("kms", region_name=region)


class AwsKmsKeyProvider:
    name = "aws-kms"

    def __init__(self, key_id: str, *, client: Any) -> None:
        self.key_id = key_id
        self._client = client

    def __repr__(self) -> str:
        return f"AwsKmsKeyProvider(key_id={self.key_id!r})"

    def is_unlocked(self) -> bool:
        """True when KMS is reachable and the key is enabled (used by /readyz)."""
        try:
            metadata = self._client.describe_key(KeyId=self.key_id)["KeyMetadata"]
        except Exception:
            return False
        return bool(metadata.get("Enabled", False))

    def wrap(self, key: bytes, context: Mapping[str, str]) -> bytes:
        try:
            response = self._client.encrypt(
                KeyId=self.key_id, Plaintext=key, EncryptionContext=dict(context)
            )
        except Exception:
            # KMS error text can name keys and contexts; keep it out of our errors.
            raise CryptoError() from None
        return bytes(response["CiphertextBlob"])

    def unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        try:
            response = self._client.decrypt(
                KeyId=self.key_id, CiphertextBlob=wrapped, EncryptionContext=dict(context)
            )
        except Exception:
            raise CryptoError() from None
        return bytes(response["Plaintext"])
