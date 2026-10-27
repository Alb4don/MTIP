from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..correlate.engine import ATTRIBUTABLE_TYPES
from ..security import InputRejected, detect_attack
from ..service import INFERRED_RELS

SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,79}$")
ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
NODE_TYPES = ("indicator", *ATTRIBUTABLE_TYPES)


def check_source_name(value: str) -> str:
    value = value.strip()
    category = detect_attack(value)
    if category:
        raise InputRejected("source name contains disallowed characters", category)
    if not SOURCE_NAME.match(value) or value.lower() == "analyst":
        raise InputRejected("source name must be 1-80 letters, digits, spaces or . _ ( ) -")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class FeedbackIn(StrictModel):
    src_type: Literal["indicator", "malware", "campaign", "intrusion-set", "tool"]
    src_id: int = Field(ge=1, le=2**53)
    dst_type: Literal["malware", "campaign", "intrusion-set", "tool"]
    dst_id: int = Field(ge=1, le=2**53)
    relation: Literal[INFERRED_RELS]
    verdict: Literal["confirm", "reject"]


class TaxiiCredentials(StrictModel):
    username: str | None = Field(default=None, max_length=256)
    password: str | None = Field(default=None, max_length=1024)

    @field_validator("username")
    @classmethod
    def _user(cls, v: str | None) -> str | None:
        if v is not None and (detect_attack(v) or any(ord(c) < 32 for c in v)):
            raise InputRejected("username contains disallowed characters", "validation")
        return v or None


class TaxiiDiscoverIn(TaxiiCredentials):
    url: str = Field(min_length=8, max_length=2048)


class TaxiiImportIn(TaxiiCredentials):
    collection_url: str = Field(min_length=8, max_length=2048)
    source_name: str = Field(min_length=1, max_length=80)
    added_after: str | None = Field(default=None, max_length=32)

    @field_validator("source_name")
    @classmethod
    def _name(cls, v: str) -> str:
        return check_source_name(v)

    @field_validator("added_after")
    @classmethod
    def _ts(cls, v: str | None) -> str | None:
        if v and not ISO_TS.match(v):
            raise InputRejected("added_after must be an ISO-8601 UTC timestamp such as 2026-01-01T00:00:00Z")
        return v or None


class CorrelationIn(StrictModel):
    min_attribution: float = Field(default=0.6, ge=0.3, le=0.99)
    ambiguity_ratio: float = Field(default=0.8, ge=0.3, le=1.0)
    fdr_alpha: float = Field(default=0.05, ge=0.001, le=0.2)
    temporal_tau_days: float = Field(default=180.0, ge=1.0, le=3650.0)
    evaluate: bool = True
