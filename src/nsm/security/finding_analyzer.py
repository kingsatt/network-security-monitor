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
    recommendation: str


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
            "recommendation": (
                "Disable Telnet and use SSH for secure remote administration."
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
            "recommendation": (
                "Disable FTP when possible and use SFTP or FTPS "
                "for encrypted file transfers."
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
            "recommendation": (
                "Restrict SMB access to trusted networks and disable "
                "unnecessary SMB exposure."
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
            "recommendation": (
                "Use HTTPS instead of unencrypted HTTP and redirect "
                "HTTP traffic to HTTPS."
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
            "recommendation": (
                "Restrict MySQL access to trusted hosts and avoid exposing "
                "the database directly to untrusted networks."
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
            "recommendation": (
                "Restrict PostgreSQL access to trusted hosts and avoid "
                "exposing the database directly to untrusted networks."
            ),
        },
        "REDIS": {
            "rule_id": "REDIS_EXPOSED",
            "severity": Severity.HIGH,
            "title": "Redis service exposed",
            "description": (
                "An exposed Redis service may allow unauthorized access "
                "if authentication and network restrictions are not "
                "properly configured."
            ),
            "recommendation": (
                "Restrict Redis access to trusted networks and require "
                "authentication where appropriate."
            ),
        },
        "RDP": {
            "rule_id": "RDP_EXPOSED",
            "severity": Severity.HIGH,
            "title": "Exposed RDP service",
            "description": (
                "An exposed RDP service increases the attack surface "
                "and may be targeted for unauthorized remote access."
            ),
            "recommendation": (
                "Restrict RDP access to trusted networks or VPN access "
                "and disable unnecessary public exposure."
            ),
        },
        "VNC": {
            "rule_id": "VNC_EXPOSED",
            "severity": Severity.HIGH,
            "title": "Exposed VNC service",
            "description": (
                "An exposed VNC service may allow unauthorized remote "
                "desktop access if it is not properly secured."
            ),
            "recommendation": (
                "Restrict VNC access to trusted networks or VPN access "
                "and use strong authentication."
            ),
        },
        "MONGODB": {
            "rule_id": "MONGODB_EXPOSED",
            "severity": Severity.HIGH,
            "title": "Exposed MongoDB service",
            "description": (
                "An exposed MongoDB service may allow unauthorized database "
                "access if authentication and network restrictions are not "
                "properly configured."
            ),
            "recommendation": (
                "Restrict MongoDB access to trusted networks and require "
                "authentication."
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
            recommendation=rule["recommendation"],
        )