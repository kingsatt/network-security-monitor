from nsm.scanner.tcp_scanner import PortScanResult
from nsm.security.risk_analyzer import RiskAnalyzer
from nsm.security.risk_models import ScanRisk
from nsm.vulnerabilities.models import Vulnerability


def assess_vulnerability_risk(
    vulnerability: Vulnerability,
    scan_result: PortScanResult,
) -> ScanRisk:
    exposed = scan_result.is_open

    assessment = RiskAnalyzer.assess(
        vulnerability=vulnerability,
        exposed=exposed,
    )

    return ScanRisk(
        port=scan_result.port,
        service=scan_result.service,
        cve_id=vulnerability.cve_id,
        risk_level=assessment.risk_level,
        risk_score=assessment.risk_score,
        reason=assessment.reason,
    )