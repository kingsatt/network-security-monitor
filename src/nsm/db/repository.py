from datetime import datetime

from sqlalchemy.orm import Session

from nsm.db.models import (
    Scan,
    ScanResult,
    SecurityFinding,
    Vulnerability,
    RiskAssessment,
)


def create_scan(
    db: Session,
    target: str,
    started_at: datetime,
) -> Scan:
    scan = Scan(
        target=target,
        started_at=started_at,
    )

    db.add(scan)
    db.flush()
    db.refresh(scan)

    return scan


def create_scan_result(
    db: Session,
    scan_id: int,
    port: int,
    is_open: bool,
    service: str | None,
    banner: str | None,
    product: str | None,
    version: str | None,
) -> ScanResult:
    result = ScanResult(
        scan_id=scan_id,
        port=port,
        is_open=is_open,
        service=service,
        banner=banner,
        product=product,
        version=version,
    )

    db.add(result)
    db.flush()
    db.refresh(result)

    return result


def get_scans(db: Session) -> list[Scan]:
    return db.query(Scan).order_by(
        Scan.id.desc()
    ).all()


def get_scan(
    db: Session,
    scan_id: int,
) -> Scan | None:
    return db.query(Scan).filter(
        Scan.id == scan_id
    ).first()


def get_scan_results(
    db: Session,
    scan_id: int,
) -> list[ScanResult]:
    return db.query(ScanResult).filter(
        ScanResult.scan_id == scan_id
    ).all()

def get_scan_findings(
    db: Session,
    scan_id: int,
) -> list[SecurityFinding]:
    return (
        db.query(SecurityFinding)
        .filter(SecurityFinding.scan_id == scan_id)
        .all()
    )

def commit(db: Session) -> None:
    db.commit()

def create_security_finding(
    db: Session,
    scan_id: int,
    rule_id: str,
    port: int,
    service: str,
    severity: str,
    title: str,
    description: str,
    recommendation: str,
) -> SecurityFinding:
    finding = SecurityFinding(
        scan_id=scan_id,
        rule_id=rule_id,
        port=port,
        service=service,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
    )

    db.add(finding)
    db.flush()
    db.refresh(finding)

    return finding

def create_vulnerability(
    db: Session,
    scan_id: int,
    cve_id: str,
    product: str,
    version: str,
    severity: str,
    cvss_score: float,
    description: str,
    port: int,
    service: str | None,
) -> Vulnerability:
    vulnerability = Vulnerability(
        scan_id=scan_id,
        cve_id=cve_id,
        product=product,
        version=version,
        severity=severity,
        cvss_score=cvss_score,
        description=description,
        port=port,
        service=service,
    )

    db.add(vulnerability)
    db.flush()
    db.refresh(vulnerability)

    return vulnerability

def get_scan_vulnerabilities(
    db: Session,
    scan_id: int,
) -> list[Vulnerability]:
    return (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan_id)
        .all()
    )

def create_risk_assessment(
    db: Session,
    scan_id: int,
    vulnerability_id: int,
    port: int,
    service: str | None,
    risk_level: str,
    risk_score: float,
    reason: str,
) -> RiskAssessment:
    risk_assessment = RiskAssessment(
        scan_id=scan_id,
        vulnerability_id=vulnerability_id,
        port=port,
        service=service,
        risk_level=risk_level,
        risk_score=risk_score,
        reason=reason,
    )

    db.add(risk_assessment)
    db.flush()
    db.refresh(risk_assessment)

    return risk_assessment

def get_scan_risk_assessments(
    db: Session,
    scan_id: int,
) -> list[RiskAssessment]:
    return (
        db.query(RiskAssessment)
        .filter(RiskAssessment.scan_id == scan_id)
        .all()
    )