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

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False,
    )

    port: Mapped[int] = mapped_column(
        nullable=False,
    )

    is_open: Mapped[bool] = mapped_column(
        nullable=False,
    )

    service: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    banner: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )