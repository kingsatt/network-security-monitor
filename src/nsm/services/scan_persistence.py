from datetime import datetime, timezone

from nsm.db.repository import (
    create_scan,
    create_scan_result,
    commit,
)


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

    scan.completed_at = datetime.now(
        timezone.utc
    )

    commit(db)

    return scan