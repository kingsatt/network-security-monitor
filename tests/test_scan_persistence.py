from datetime import datetime, timezone

from nsm.db.repository import (
    get_scan_results,
    get_scan_vulnerabilities,
    get_scan_risk_assessments,
)
from nsm.scanner.tcp_scanner import PortScanResult
from nsm.services.scan_persistence import save_scan
from nsm.vulnerabilities.mock_provider import MockProvider
from nsm.vulnerabilities.scanner import VulnerabilityScanner


def test_save_scan_persists_product_and_version(db):
    results = [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner="SSH-2.0-OpenSSH_9.9",
            product="OpenSSH",
            version="9.9",
        )
    ]

    scan = save_scan(
        db=db,
        target="127.0.0.1",
        results=results,
    )

    saved_results = get_scan_results(db, scan.id)

    assert len(saved_results) == 1
    assert saved_results[0].product == "OpenSSH"
    assert saved_results[0].version == "9.9"

def test_save_scan_persists_vulnerability(db):
    results = [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner="SSH-2.0-OpenSSH_9.9",
            product="OpenSSH",
            version="9.9",
        )
    ]

    vulnerability_scanner = VulnerabilityScanner(
        provider=MockProvider(),
    )

    scan = save_scan(
        db=db,
        target="127.0.0.1",
        results=results,
        vulnerability_scanner=vulnerability_scanner,
    )

    vulnerabilities = get_scan_vulnerabilities(
        db=db,
        scan_id=scan.id,
    )

    assert len(vulnerabilities) == 1

    vulnerability = vulnerabilities[0]

    assert vulnerability.cve_id == "CVE-2025-1234"
    assert vulnerability.product == "OpenSSH"
    assert vulnerability.version == "9.9"
    assert vulnerability.severity == "HIGH"
    assert vulnerability.cvss_score == 8.8
    assert vulnerability.port == 22
    assert vulnerability.service == "SSH"

def test_save_scan_persists_risk_assessment(db):
    results = [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner="SSH-2.0-OpenSSH_9.9",
            product="OpenSSH",
            version="9.9",
        )
    ]

    vulnerability_scanner = VulnerabilityScanner(
        provider=MockProvider(),
    )

    scan = save_scan(
        db=db,
        target="127.0.0.1",
        results=results,
        vulnerability_scanner=vulnerability_scanner,
    )

    risks = get_scan_risk_assessments(
        db=db,
        scan_id=scan.id,
    )

    assert len(risks) == 1

    risk = risks[0]

    assert risk.port == 22
    assert risk.service == "SSH"
    assert risk.risk_level == "CRITICAL"
    assert risk.risk_score == 9.8
    assert "CVE-2025-1234" in risk.reason
    assert "exposed" in risk.reason