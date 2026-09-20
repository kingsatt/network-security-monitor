from dataclasses import dataclass

from nsm.vulnerabilities.models import Vulnerability


@dataclass
class RiskAssessment:
    risk_level: str
    risk_score: float
    reason: str


class RiskAnalyzer:
    @staticmethod
    def assess(
        vulnerability: Vulnerability,
        exposed: bool,
    ) -> RiskAssessment:
        risk_score = vulnerability.cvss_score

        if exposed:
            risk_score = min(risk_score + 1.0, 10.0)

        if risk_score >= 9.0:
            risk_level = "CRITICAL"
        elif risk_score >= 7.0:
            risk_level = "HIGH"
        elif risk_score >= 4.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        if exposed:
            reason = (
                f"{vulnerability.cve_id} affects "
                f"{vulnerability.product} {vulnerability.version} "
                f"and the service is exposed."
            )
        else:
            reason = (
                f"{vulnerability.cve_id} affects "
                f"{vulnerability.product} {vulnerability.version}, "
                f"but the service is not exposed."
            )

        return RiskAssessment(
            risk_level=risk_level,
            risk_score=risk_score,
            reason=reason,
        )