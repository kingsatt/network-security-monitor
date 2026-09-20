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

class VulnerabilityResponse(BaseModel):
    cve_id: str
    product: str
    version: str
    severity: str
    cvss_score: float
    description: str
    port: int
    service: str | None = None

class RiskAssessmentResponse(BaseModel):
    port: int
    service: str | None = None
    vulnerability_id: int
    risk_level: str
    risk_score: float
    reason: str

class SeverityCountsResponse(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardSummaryResponse(BaseModel):
    id: int
    target: str
    started_at: datetime
    completed_at: datetime | None = None

    total_ports: int
    open_ports: int

    findings: SeverityCountsResponse
    vulnerabilities: SeverityCountsResponse
    risks: SeverityCountsResponse

class ScanDetailResponse(BaseModel):
    id: int
    target: str
    started_at: datetime
    completed_at: datetime | None = None
    results: list[ScanResultResponse]
    findings: list[SecurityFindingResponse]
    vulnerabilities: list[VulnerabilityResponse]
    risk_assessments: list[RiskAssessmentResponse]

class ScanResponse(BaseModel):
    target: str
    results: list[ScanResultResponse]
    findings: list[SecurityFindingResponse]