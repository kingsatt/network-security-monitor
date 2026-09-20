from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import ForeignKey

from nsm.db.database import Base



class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    target: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    is_open: Mapped[bool] = mapped_column(nullable=False)
    service: Mapped[str | None] = mapped_column(String(100), nullable=True)
    banner: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    product: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)

class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
    )

    rule_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    port: Mapped[int] = mapped_column(
        nullable=False,
    )

    service: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

    recommendation: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
    )

    cve_id: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    product: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    cvss_score: Mapped[float] = mapped_column(
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
    )

    port: Mapped[int] = mapped_column(
        nullable=False,
    )

    service: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
    )

    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id"),
        nullable=False,
    )

    port: Mapped[int] = mapped_column(
        nullable=False,
    )

    service: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    risk_score: Mapped[float] = mapped_column(
        nullable=False,
    )

    reason: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
    )