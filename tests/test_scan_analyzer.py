from nsm.scanner.tcp_scanner import PortScanResult
from nsm.security.scan_analyzer import analyze_scan


def test_analyze_scan_returns_findings():
    results = [
        PortScanResult(
            port=23,
            is_open=True,
            service="TELNET",
        ),
        PortScanResult(
            port=80,
            is_open=False,
            service=None,
        ),
    ]

    findings = analyze_scan(results)

    assert len(findings) == 1

    assert findings[0].rule_id == "TELNET_EXPOSED"