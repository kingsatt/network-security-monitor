from nsm.scanner.tcp_scanner import PortScanResult
from nsm.security.finding_analyzer import (
    FindingAnalyzer,
    Severity,
)


def test_telnet_open_port_creates_high_severity_finding():
    result = PortScanResult(
        port=23,
        is_open=True,
        service="TELNET",
    )

    analyzer = FindingAnalyzer()

    finding = analyzer.analyze(result)

    assert finding is not None
    assert finding.port == 23
    assert finding.service == "TELNET"
    assert finding.severity == Severity.HIGH
    assert finding.title == "Insecure Telnet service exposed"
    assert finding.rule_id == "TELNET_EXPOSED"
    assert "without encryption" in finding.description

def test_ftp_open_port_creates_medium_severity_finding():
    result = PortScanResult(
        port=21,
        is_open=True,
        service="FTP",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.severity == Severity.MEDIUM
    assert finding.title == "FTP service exposed"


def test_smb_open_port_creates_medium_severity_finding():
    result = PortScanResult(
        port=445,
        is_open=True,
        service="SMB",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.severity == Severity.MEDIUM
    assert finding.title == "SMB service exposed"


def test_http_open_port_creates_low_severity_finding():
    result = PortScanResult(
        port=80,
        is_open=True,
        service="HTTP",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.severity == Severity.LOW
    assert finding.title == "Unencrypted HTTP service exposed"


def test_mysql_open_port_creates_high_severity_finding():
    result = PortScanResult(
        port=3306,
        is_open=True,
        service="MYSQL",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.title == "MySQL database service exposed"


def test_postgresql_open_port_creates_high_severity_finding():
    result = PortScanResult(
        port=5432,
        is_open=True,
        service="POSTGRESQL",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.title == "PostgreSQL database service exposed"


def test_redis_open_port_creates_high_severity_finding():
    result = PortScanResult(
        port=6379,
        is_open=True,
        service="REDIS",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.title == "Redis service exposed"

def test_closed_port_does_not_create_finding():
    result = PortScanResult(
        port=23,
        is_open=False,
        service="TELNET",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is None


def test_unknown_service_does_not_create_finding():
    result = PortScanResult(
        port=9999,
        is_open=True,
        service="UNKNOWN",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is None

def test_rdp_exposed():
    result = PortScanResult(
        port=3389,
        is_open=True,
        service="RDP",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.rule_id == "RDP_EXPOSED"
    assert finding.severity == Severity.HIGH


def test_vnc_exposed():
    result = PortScanResult(
        port=5900,
        is_open=True,
        service="VNC",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.rule_id == "VNC_EXPOSED"
    assert finding.severity == Severity.HIGH


def test_mongodb_exposed():
    result = PortScanResult(
        port=27017,
        is_open=True,
        service="MONGODB",
    )

    finding = FindingAnalyzer().analyze(result)

    assert finding is not None
    assert finding.rule_id == "MONGODB_EXPOSED"
    assert finding.severity == Severity.HIGH