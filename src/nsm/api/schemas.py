from datetime import datetime

from pydantic import BaseModel


class ScanRequest(BaseModel):
    target: str
    ports: list[int]


class ScanResultResponse(BaseModel):
    port: int
    is_open: bool
    service: str | None = None
    banner: str | None = None


class ScanResponse(BaseModel):
    target: str
    results: list[ScanResultResponse]


class ScanSummaryResponse(BaseModel):
    id: int
    target: str
    started_at: datetime
    completed_at: datetime | None = None


class ScanDetailResponse(BaseModel):
    id: int
    target: str
    started_at: datetime
    completed_at: datetime | None = None
    results: list[ScanResultResponse]