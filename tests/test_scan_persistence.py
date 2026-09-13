from datetime import datetime, timezone

from nsm.db.repository import get_scan_results
from nsm.scanner.tcp_scanner import PortScanResult
from nsm.services.scan_persistence import save_scan


def test_save_scan_persists_product_and_version(db):
    results = [
        PortScanResult(
            port=22,
            is_open=True,
            service="SSH",
            banner="SSH-2.0-OpenSSH_9.9",
            product="OpenSSH",
            version="9.9",
        )
    ]

    scan = save_scan(
        db=db,
        target="127.0.0.1",
        results=results,
    )

    saved_results = get_scan_results(db, scan.id)

    assert len(saved_results) == 1
    assert saved_results[0].product == "OpenSSH"
    assert saved_results[0].version == "9.9"