from dataclasses import dataclass


@dataclass
class ScanRisk:
    port: int
    service: str | None
    cve_id: str
    risk_level: str
    risk_score: float
    reason: str