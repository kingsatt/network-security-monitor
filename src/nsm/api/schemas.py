from datetime import datetime

from typing import Annotated

from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    model_config = {
        "str_strip_whitespace": True,
    }

    target: str = Field(min_length=1)
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        min_length=1
    )


class ScanResultResponse(BaseModel):
    port: int
    is_open: bool
    service: str | None = None
    banner: str | None = None
    product: str | None = None
    version: str | None = None


class ScanSummaryResponse(BaseModel):
    id: int
    target: str
    started_at: datetime
    completed_at: datetime | None = None


class SecurityFindingResponse(BaseModel):
    rule_id: str
    port: int
    service: str
    severity: str
    title: str
    description: str
    recommendation: str

class ScanDetailResponse(BaseModel):
    id: int
    target: str
    started_at: datetime
    completed_at: datetime | None = None
    results: list[ScanResultResponse]
    findings: list[SecurityFindingResponse]

class ScanResponse(BaseModel):
    target: str
    results: list[ScanResultResponse]
    findings: list[SecurityFindingResponse]