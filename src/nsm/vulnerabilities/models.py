from dataclasses import dataclass


@dataclass
class Vulnerability:
    cve_id: str
    product: str
    version: str
    severity: str
    cvss_score: float
    description: str
    port: int | None = None
    service: str | None = None