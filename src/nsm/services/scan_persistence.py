from datetime import datetime, timezone

from nsm.db.repository import (
    create_scan,
    create_scan_result,
    create_security_finding,
    create_vulnerability,
    create_risk_assessment,
    commit,
)

from nsm.security.scan_analyzer import analyze_scan
from nsm.security.risk_service import assess_vulnerability_risk
from nsm.vulnerabilities.scan_vulnerability_analyzer import (
    analyze_scan_vulnerabilities,
)


def save_scan(
    db,
    target: str,
    results,
    vulnerability_scanner=None,
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
            product=result.product,
            version=result.version,
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

    if vulnerability_scanner is not None:
        vulnerabilities = analyze_scan_vulnerabilities(
            results=results,
            scanner=vulnerability_scanner,
        )

        for vulnerability in vulnerabilities:
            saved_vulnerability = create_vulnerability(
                db=db,
                scan_id=scan.id,
                cve_id=vulnerability.cve_id,
                product=vulnerability.product,
                version=vulnerability.version,
                severity=vulnerability.severity,
                cvss_score=vulnerability.cvss_score,
                description=vulnerability.description,
                port=vulnerability.port,
                service=vulnerability.service,
            )

            for result in results:
                if result.port != vulnerability.port:
                    continue

                risk = assess_vulnerability_risk(
                    vulnerability=vulnerability,
                    scan_result=result,
                )

                create_risk_assessment(
                    db=db,
                    scan_id=scan.id,
                    vulnerability_id=saved_vulnerability.id,
                    port=risk.port,
                    service=risk.service,
                    risk_level=risk.risk_level,
                    risk_score=risk.risk_score,
                    reason=risk.reason,
                )

    scan.completed_at = datetime.now(timezone.utc)

    commit(db)

    return scan