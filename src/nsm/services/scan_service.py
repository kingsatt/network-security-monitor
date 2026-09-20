from nsm.db.database import SessionLocal
from nsm.scanner.tcp_scanner import TCPScanner
from nsm.services.scan_persistence import save_scan
from nsm.vulnerabilities.mock_provider import MockProvider
from nsm.vulnerabilities.scanner import VulnerabilityScanner

def perform_scan(
    target: str,
    ports: list[int],
):
    scanner = TCPScanner(target)

    return scanner.scan_ports_concurrent(
        ports
    )

def run_scan(
    target: str,
    ports: list[int],
):
    results = perform_scan(
        target=target,
        ports=ports,
    )

    vulnerability_scanner = VulnerabilityScanner(
        provider=MockProvider(),
    )

    db = SessionLocal()

    try:
        save_scan(
            db=db,
            target=target,
            results=results,
            vulnerability_scanner=vulnerability_scanner,
        )

        return results

    finally:
        db.close()