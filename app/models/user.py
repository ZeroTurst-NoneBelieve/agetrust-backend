from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, Boolean, CheckConstraint, Integer, String, false, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    """설계서 01. users

    KIOSK 계정(#66)은 관리자가 만들고 전화번호가 없다.
    USER·ADMIN 계정은 지금처럼 인증된 전화번호가 필수다.
    """

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("platform_role IN ('USER', 'ADMIN', 'KIOSK')", name="ck_users_platform_role"),
        CheckConstraint("status IN ('ACTIVE', 'SUSPENDED', 'WITHDRAWN')", name="ck_users_status"),
        CheckConstraint(
            "platform_role = 'KIOSK' OR (phone_number IS NOT NULL AND phone_verified_at IS NOT NULL)",
            name="ck_users_phone_required_except_kiosk",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    login_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    phone_number: Mapped[str | None] = mapped_column(String(30), unique=True, nullable=True)
    phone_verified_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    platform_role: Mapped[str] = mapped_column(String(30), nullable=False, server_default="USER")
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="ACTIVE")
    # 관리자가 발급한 임시 비밀번호 상태. 바꾸기 전에는 비밀번호 변경과 내 정보 조회만 허용한다.
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=false())
    temp_password_expires_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    # 정지·비밀번호 초기화·변경 때 1씩 올려, 그 전에 발급한 토큰을 모두 무효로 만든다.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    withdrawn_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
