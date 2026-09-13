from dataclasses import dataclass
from enum import Enum

from nsm.scanner.tcp_scanner import PortScanResult


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class SecurityFinding:
    rule_id: str
    port: int
    service: str
    severity: Severity
    title: str
    description: str


class FindingAnalyzer:
    SERVICE_RULES = {
        "TELNET": {
            "rule_id": "TELNET_EXPOSED",
            "severity": Severity.HIGH,
            "title": "Insecure Telnet service exposed",
            "description": (
                "Telnet transmits data without encryption and may expose "
                "credentials and other sensitive information."
            ),
        },
        "FTP": {
            "rule_id": "FTP_EXPOSED",
            "severity": Severity.MEDIUM,
            "title": "FTP service exposed",
            "description": (
                "FTP commonly transmits credentials and data without "
                "encryption."
            ),
        },
        "SMB": {
            "rule_id": "SMB_EXPOSED",
            "severity": Severity.MEDIUM,
            "title": "SMB service exposed",
            "description": (
                "An exposed SMB service may increase the attack surface "
                "of the host."
            ),
        },
        "HTTP": {
            "rule_id": "HTTP_UNENCRYPTED",
            "severity": Severity.LOW,
            "title": "Unencrypted HTTP service exposed",
            "description": (
                "HTTP does not encrypt application traffic, allowing "
                "network traffic to potentially be observed or modified."
            ),
        },
        "MYSQL": {
            "rule_id": "MYSQL_EXPOSED",
            "severity": Severity.HIGH,
            "title": "MySQL database service exposed",
            "description": (
                "An exposed database service increases the attack surface "
                "and may allow unauthorized access if improperly secured."
            ),
        },
        "POSTGRESQL": {
            "rule_id": "POSTGRESQL_EXPOSED",
            "severity": Severity.HIGH,
            "title": "PostgreSQL database service exposed",
            "description": (
                "An exposed database service increases the attack surface "
                "and may allow unauthorized access if improperly secured."
            ),
        },
        "REDIS": {
            "rule_id": "REDIS_EXPOSED",
            "severity": Severity.HIGH,
            "title": "Redis service exposed",
            "description": (
                "An exposed Redis service may allow unauthorized access "
                "if authentication and network restrictions are not properly configured."
            ),
        },
    }

    def analyze(
        self,
        result: PortScanResult,
    ) -> SecurityFinding | None:
        if not result.is_open:
            return None

        if result.service is None:
            return None

        rule = self.SERVICE_RULES.get(result.service)

        if rule is None:
            return None

        return SecurityFinding(
            rule_id=rule["rule_id"],
            port=result.port,
            service=result.service,
            severity=rule["severity"],
            title=rule["title"],
            description=rule["description"],
        )