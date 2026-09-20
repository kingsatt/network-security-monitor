from nsm.scanner.tcp_scanner import PortScanResult
from nsm.security.risk_service import assess_vulnerability_risk
from nsm.vulnerabilities.models import Vulnerability


def make_vulnerability() -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2025-1234",
        product="OpenSSH",
        version="9.9",
        severity="HIGH",
        cvss_score=6.5,
        description="Test vulnerability",
    )


def test_assess_exposed_vulnerability():
    vulnerability = make_vulnerability()

    scan_result = PortScanResult(
        port=22,
        is_open=True,
        service="SSH",
        product="OpenSSH",
        version="9.9",
    )

    result = assess_vulnerability_risk(
        vulnerability=vulnerability,
        scan_result=scan_result,
    )

    assert result.port == 22
    assert result.service == "SSH"
    assert result.cve_id == "CVE-2025-1234"
    assert result.risk_score == 7.5
    assert result.risk_level == "HIGH"


def test_assess_unexposed_vulnerability():
    vulnerability = make_vulnerability()

    scan_result = PortScanResult(
        port=22,
        is_open=False,
        service="SSH",
        product="OpenSSH",
        version="9.9",
    )

    result = assess_vulnerability_risk(
        vulnerability=vulnerability,
        scan_result=scan_result,
    )

    assert result.risk_score == 6.5
    assert result.risk_level == "MEDIUM"