"""Typed IPC contract for the authenticated admission-control producer."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from fieldtrue.domain import FrozenModel, GitObjectId, Identifier, Sha256

CONTROL_PRODUCER_OPERATION = "generate-iter001-admission-controls"
CONTROL_PRODUCER_RECEIPT_PATH = ".local/admission-controls/control_suite_receipt.json"
CONTROL_PRODUCER_KEY_PATH = ".local/keys/iter001-control-fixture.ed25519"
CONTROL_PRODUCER_SNAPSHOT_PATHS = (
    "pyproject.toml",
    "uv.lock",
    "protocol/acquisition/iter001_contract.json",
    "src/fieldtrue",
    "tests/__init__.py",
    "tests/acquisition_helpers.py",
    "tests/unit/__init__.py",
    "tests/unit/test_acquisition.py",
)
MAX_CONTROL_PRODUCER_REQUEST_BYTES = 16 * 1024
MAX_CONTROL_PRODUCER_RESPONSE_BYTES = 16 * 1024


class ControlAuthorityError(RuntimeError):
    """Control evidence or producer authority is incomplete, ambiguous, or untrusted."""


class ControlProducerRequest(FrozenModel):
    schema_version: Literal["fieldtrue.control-producer-request.v1"] = (
        "fieldtrue.control-producer-request.v1"
    )
    operation: Literal["generate-iter001-admission-controls"] = (
        "generate-iter001-admission-controls"
    )
    request_id: Sha256
    repository_root: str = Field(min_length=1, max_length=4096)
    execution_commit: GitObjectId
    execution_tree: GitObjectId
    timeout_seconds: int = Field(ge=1, le=3600)

    @model_validator(mode="after")
    def repository_is_absolute_and_normalized(self) -> Self:
        candidate = Path(self.repository_root)
        if not candidate.is_absolute() or str(candidate) != self.repository_root:
            raise ValueError("producer repository root must be an absolute normalized path")
        return self


class ControlProducerResponse(FrozenModel):
    schema_version: Literal["fieldtrue.control-producer-response.v1"] = (
        "fieldtrue.control-producer-response.v1"
    )
    request_id: Sha256
    request_sha256: Sha256
    status: Literal["published", "rejected"]
    failure_code: Identifier | None = None
    execution_commit: GitObjectId | None = None
    execution_tree: GitObjectId | None = None
    receipt_sha256: Sha256 | None = None
    published_path: Literal[".local/admission-controls/control_suite_receipt.json"] | None = None
    control_count: Literal[22] | None = None

    @model_validator(mode="after")
    def fields_match_status(self) -> Self:
        authority_fields = (
            self.execution_commit,
            self.execution_tree,
            self.receipt_sha256,
            self.published_path,
            self.control_count,
        )
        if self.status == "published":
            if self.failure_code is not None or any(value is None for value in authority_fields):
                raise ValueError("published producer response is incomplete")
        elif self.failure_code is None or any(value is not None for value in authority_fields):
            raise ValueError("rejected producer response exposes authority fields")
        return self
