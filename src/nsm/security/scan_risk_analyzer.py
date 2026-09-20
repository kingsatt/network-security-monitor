from nsm.scanner.tcp_scanner import PortScanResult
from nsm.security.risk_service import assess_vulnerability_risk
from nsm.security.risk_models import ScanRisk
from nsm.vulnerabilities.models import Vulnerability


def analyze_scan_risks(
    results: list[PortScanResult],
    vulnerabilities: list[Vulnerability],
) -> list[ScanRisk]:
    risks = []

    for vulnerability in vulnerabilities:
        for result in results:
            if result.port != vulnerability.port:
                continue

            risk = assess_vulnerability_risk(
                vulnerability=vulnerability,
                scan_result=result,
            )

            risks.append(risk)

    return risks