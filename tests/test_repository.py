from datetime import datetime

from nsm.db.models import SecurityFinding
from nsm.db.repository import (
    create_scan,
    create_security_finding,
    get_scan_findings,
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