"""AWS KMS key provider: the master key never leaves KMS.

Tenant keys are wrapped with ``kms:Encrypt`` and unwrapped with ``kms:Decrypt``; the wrap
context (purpose, tenant, version) is sent as the KMS *encryption context*, so KMS itself
refuses to unwrap a key for the wrong tenant, and every use shows up in CloudTrail.

The IAM role needs ``kms:Encrypt``, ``kms:Decrypt`` and ``kms:DescribeKey`` on the key.
boto3 is an optional dependency (``pip install securedb[kms]``).
"""

import time
from collections.abc import Callable, Mapping
from typing import Any

import structlog

from securedb.errors import CryptoError, KeyProviderLocked

READINESS_CACHE_SECONDS = 30.0
# Error codes that mean "this ciphertext or context is wrong", as opposed to "KMS is
# unreachable, throttling or denying us". Only these are reported as crypto failures.
_TAMPER_CODES = frozenset({"InvalidCiphertextException", "IncorrectKeyException"})

log = structlog.get_logger(__name__)


class KmsUnavailable(Exception):
    """boto3 is not installed or a client could not be created."""


def default_client(region: str | None) -> Any:
    try:
        import boto3  # type: ignore[import-not-found,unused-ignore]
        from botocore.config import Config  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        raise KmsUnavailable("AWS KMS support needs boto3: install securedb[kms].") from None
    # Calls happen inside database transactions: fail fast instead of holding connections.
    config = Config(
        connect_timeout=2, read_timeout=5, retries={"mode": "standard", "max_attempts": 3}
    )
    return boto3.client("kms", region_name=region, config=config)


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        code = response.get("Error", {}).get("Code")
        return code if isinstance(code, str) else None
    return None


class AwsKmsKeyProvider:
    name = "aws-kms"

    def __init__(
        self, key_id: str, *, client: Any, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.key_id = key_id
        self._client = client
        self._clock = clock
        self._ready: tuple[float, bool] | None = None

    def __repr__(self) -> str:
        return f"AwsKmsKeyProvider(key_id={self.key_id!r})"

    def is_unlocked(self) -> bool:
        """True when KMS is reachable and the key is enabled (used by /readyz).

        Cached briefly so that readiness probes do not turn into KMS traffic.
        """
        now = self._clock()
        if self._ready is not None and now - self._ready[0] < READINESS_CACHE_SECONDS:
            return self._ready[1]
        try:
            metadata = self._client.describe_key(KeyId=self.key_id)["KeyMetadata"]
            ready = bool(metadata.get("Enabled", False))
        except Exception as exc:
            self._log("describe_key", exc)
            ready = False
        self._ready = (now, ready)
        return ready

    def wrap(self, key: bytes, context: Mapping[str, str]) -> bytes:
        try:
            response = self._client.encrypt(
                KeyId=self.key_id, Plaintext=key, EncryptionContext=dict(context)
            )
        except Exception as exc:
            raise self._translate("encrypt", exc) from None
        return bytes(response["CiphertextBlob"])

    def unwrap(self, wrapped: bytes, context: Mapping[str, str]) -> bytes:
        try:
            response = self._client.decrypt(
                KeyId=self.key_id, CiphertextBlob=wrapped, EncryptionContext=dict(context)
            )
        except Exception as exc:
            raise self._translate("decrypt", exc) from None
        return bytes(response["Plaintext"])

    def _log(self, operation: str, exc: Exception) -> str | None:
        # The AWS error *code* is safe to log; the message can name keys and contexts.
        code = _error_code(exc)
        log.warning("kms_error", operation=operation, error_type=type(exc).__name__, code=code)
        return code

    def _translate(self, operation: str, exc: Exception) -> Exception:
        if self._log(operation, exc) in _TAMPER_CODES:
            return CryptoError()
        return KeyProviderLocked("The key service is unavailable. Try again shortly.")
