from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, CheckConstraint, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Business(Base):
    """설계서 05. businesses

    사업자등록번호는 users.role이 아니라 businesses에 둔다.
    """

    __tablename__ = "businesses"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED', 'TERMINATED')",
            name="ck_businesses_status",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    business_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    business_name: Mapped[str] = mapped_column(String(200), nullable=False)
    contact_number: Mapped[str | None] = mapped_column(String(30), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
