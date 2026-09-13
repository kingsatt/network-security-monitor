from datetime import datetime

from sqlalchemy.orm import Session

from nsm.db.models import Scan, ScanResult, SecurityFinding


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