from datetime import datetime, timezone

from nsm.db.repository import (
    create_scan,
    create_scan_result,
    create_security_finding,
    commit,
)
from nsm.security.scan_analyzer import analyze_scan


def save_scan(
    db,
    target: str,
    results,
):
    scan = create_scan(
        db=db,
        target=target,
        started_at=datetime.now(timezone.utc),
    )

    for result in results:
        create_scan_result(
            db=db,
            scan_id=scan.id,
            port=result.port,
            is_open=result.is_open,
            service=result.service,
            banner=result.banner,
        )

    findings = analyze_scan(results)

    for finding in findings:
        create_security_finding(
            db=db,
            scan_id=scan.id,
            rule_id=finding.rule_id,
            port=finding.port,
            service=finding.service,
            severity=finding.severity.value,
            title=finding.title,
            description=finding.description,
            recommendation=finding.recommendation,
        )

    scan.completed_at = datetime.now(timezone.utc)

    commit(db)

    return scan