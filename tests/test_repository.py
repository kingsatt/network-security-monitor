from datetime import datetime

from nsm.db.models import SecurityFinding
from nsm.db.repository import (
    create_scan,
    create_scan_result,
    create_security_finding,
    create_vulnerability,
    create_risk_assessment,
    get_scan_findings,
    get_scan_risk_assessments,
    commit,
)
from nsm.security.risk_service import assess_vulnerability_risk
from nsm.security.scan_analyzer import analyze_scan
from nsm.vulnerabilities.scan_vulnerability_analyzer import (
    analyze_scan_vulnerabilities,
)


def test_get_scan_findings(db):
    scan = create_scan(
        db=db,
        target="127.0.0.1",
        started_at=datetime.utcnow(),
    )

    create_security_finding(
        db=db,
        scan_id=scan.id,
        rule_id="TELNET_EXPOSED",
        port=23,
        service="TELNET",
        severity="HIGH",
        title="Insecure Telnet service exposed",
        description="Telnet transmits data without encryption.",
        recommendation="Disable Telnet and use SSH.",
    )

    db.commit()

    findings = get_scan_findings(
        db=db,
        scan_id=scan.id,
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "TELNET_EXPOSED"
    assert findings[0].port == 23
    assert findings[0].severity == "HIGH"

def test_create_risk_assessment(db):
    scan = create_scan(
        db,
        target="127.0.0.1",
        started_at=datetime.utcnow(),
    )

    vulnerability = create_vulnerability(
        db=db,
        scan_id=scan.id,
        cve_id="CVE-2025-1234",
        product="OpenSSH",
        version="9.9",
        severity="HIGH",
        cvss_score=6.5,
        description="Test vulnerability",
        port=22,
        service="SSH",
    )

    risk = create_risk_assessment(
        db=db,
        scan_id=scan.id,
        vulnerability_id=vulnerability.id,
        port=22,
        service="SSH",
        risk_level="HIGH",
        risk_score=7.5,
        reason="Service is exposed.",
    )

    assert risk.id is not None
    assert risk.scan_id == scan.id
    assert risk.vulnerability_id == vulnerability.id
    assert risk.port == 22
    assert risk.service == "SSH"
    assert risk.risk_level == "HIGH"
    assert risk.risk_score == 7.5
    assert risk.reason == "Service is exposed."

def test_get_scan_risk_assessments(db):
    scan = create_scan(
        db,
        target="127.0.0.1",
        started_at=datetime.utcnow(),
    )

    vulnerability = create_vulnerability(
        db=db,
        scan_id=scan.id,
        cve_id="CVE-2025-1234",
        product="OpenSSH",
        version="9.9",
        severity="HIGH",
        cvss_score=6.5,
        description="Test vulnerability",
        port=22,
        service="SSH",
    )

    create_risk_assessment(
        db=db,
        scan_id=scan.id,
        vulnerability_id=vulnerability.id,
        port=22,
        service="SSH",
        risk_level="HIGH",
        risk_score=7.5,
        reason="Service is exposed.",
    )

    risks = get_scan_risk_assessments(
        db=db,
        scan_id=scan.id,
    )

    assert len(risks) == 1
    assert risks[0].vulnerability_id == vulnerability.id
    assert risks[0].risk_level == "HIGH"
    assert risks[0].risk_score == 7.5