from collections.abc import Generator

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from nsm.api.schemas import (
    ScanDetailResponse,
    ScanRequest,
    ScanResponse,
    ScanResultResponse,
    ScanSummaryResponse,
    SecurityFindingResponse,
)
from nsm.db.database import SessionLocal
from nsm.db.repository import (
    get_scan,
    get_scan_findings,
    get_scan_results,
    get_scans,
)
from nsm.security.scan_analyzer import analyze_scan
from nsm.services.scan_service import run_scan


router = APIRouter()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    results = run_scan(
        target=request.target,
        ports=request.ports,
    )

    response_results = [
        ScanResultResponse(
            port=result.port,
            is_open=result.is_open,
            service=result.service,
            banner=result.banner,
            product=result.product,
            version=result.version,
        )
        for result in results
    ]

    findings = analyze_scan(results)

    response_findings = [
        SecurityFindingResponse(
            rule_id=finding.rule_id,
            port=finding.port,
            service=finding.service,
            severity=finding.severity.value,
            title=finding.title,
            description=finding.description,
            recommendation=finding.recommendation,
        )
        for finding in findings
    ]

    return ScanResponse(
        target=request.target,
        results=response_results,
        findings=response_findings,
    )


@router.get(
    "/scans",
    response_model=list[ScanSummaryResponse],
)
def list_scans(
    db: Session = Depends(get_db),
):
    scans = get_scans(db)

    return [
        ScanSummaryResponse(
            id=scan.id,
            target=scan.target,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
        )
        for scan in scans
    ]


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
)
def get_scan_by_id(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = get_scan(db, scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    results = get_scan_results(
        db,
        scan.id,
    )

    findings = get_scan_findings(
        db,
        scan.id,
    )

    response_results = [
        ScanResultResponse(
            port=result.port,
            is_open=result.is_open,
            service=result.service,
            banner=result.banner,
            product=result.product,
            version=result.version,
        )
        for result in results
    ]

    response_findings = [
        SecurityFindingResponse(
            rule_id=finding.rule_id,
            port=finding.port,
            service=finding.service,
            severity=finding.severity,
            title=finding.title,
            description=finding.description,
            recommendation=finding.recommendation,
        )
        for finding in findings
    ]

    return ScanDetailResponse(
        id=scan.id,
        target=scan.target,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        results=response_results,
        findings=response_findings,
    )