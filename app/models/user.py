from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, CheckConstraint, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    """설계서 01. users"""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("platform_role IN ('USER', 'ADMIN')", name="ck_users_platform_role"),
        CheckConstraint("status IN ('ACTIVE', 'SUSPENDED', 'WITHDRAWN')", name="ck_users_status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    login_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    phone_number: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    phone_verified_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    platform_role: Mapped[str] = mapped_column(String(30), nullable=False, server_default="USER")
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    withdrawn_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
