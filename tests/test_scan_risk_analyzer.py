from nsm.scanner.tcp_scanner import PortScanResult
from nsm.security.scan_risk_analyzer import analyze_scan_risks
from nsm.vulnerabilities.models import Vulnerability


def make_vulnerability(
    port: int,
) -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2025-1234",
        product="OpenSSH",
        version="9.9",
        severity="HIGH",
        cvss_score=6.5,
        description="Test vulnerability",
        port=port,
        service="SSH",
    )


def test_analyze_scan_risks_matches_vulnerability_to_port():
    results = [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            product="OpenSSH",
            version="9.9",
        ),
        PortScanResult(
            port=80,
            is_open=True,
            service="HTTP",
        ),
    ]

    vulnerabilities = [
        make_vulnerability(port=22),
    ]

    risks = analyze_scan_risks(
        results=results,
        vulnerabilities=vulnerabilities,
    )

    assert len(risks) == 1
    assert risks[0].port == 22
    assert risks[0].cve_id == "CVE-2025-1234"
    assert risks[0].risk_score == 7.5
    assert risks[0].risk_level == "HIGH"


def test_analyze_scan_risks_ignores_unmatched_port():
    results = [
        PortScanResult(
            port=80,
            is_open=True,
            service="HTTP",
        ),
    ]

    vulnerabilities = [
        make_vulnerability(port=22),
    ]

    risks = analyze_scan_risks(
        results=results,
        vulnerabilities=vulnerabilities,
    )

    assert risks == []


def test_analyze_scan_risks_handles_multiple_vulnerabilities():
    results = [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            product="OpenSSH",
            version="9.9",
        ),
    ]

    vulnerabilities = [
        make_vulnerability(port=22),
        Vulnerability(
            cve_id="CVE-2025-5678",
            product="OpenSSH",
            version="9.9",
            severity="MEDIUM",
            cvss_score=4.5,
            description="Another vulnerability",
            port=22,
            service="SSH",
        ),
    ]

    risks = analyze_scan_risks(
        results=results,
        vulnerabilities=vulnerabilities,
    )

    assert len(risks) == 2
    assert risks[0].risk_score == 7.5
    assert risks[1].risk_score == 5.5