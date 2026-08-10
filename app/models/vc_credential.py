from datetime import datetime

from sqlalchemy import (
    TIMESTAMP,
    BigInteger,
    CheckConstraint,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class VcCredential(Base):
    """설계서 11. vc_credentials

    id(DB PK), user_id(FK), credential_id(VC 식별자)는 서로 역할이 다르다.
    vc_jwt 원문은 서버 DB에 저장하지 않는다.
    """

    __tablename__ = "vc_credentials"
    __table_args__ = (
        UniqueConstraint(
            "status_list_id", "status_list_index", name="uq_vc_credentials_status_list_position"
        ),
        CheckConstraint(
            "status IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')",
            name="ck_vc_credentials_status",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("devices.id"), nullable=False)
    adult_verification_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("adult_verifications.id"), nullable=False
    )
    credential_id: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    holder_did: Mapped[str] = mapped_column(String(500), nullable=False)
    issuer_did: Mapped[str] = mapped_column(String(500), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(100), nullable=False, server_default="AdultCredential")
    credential_format: Mapped[str | None] = mapped_column(String(50), nullable=True)
    credential_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="ACTIVE")
    status_list_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("credential_status_lists.id"), nullable=True
    )
    status_list_index: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
