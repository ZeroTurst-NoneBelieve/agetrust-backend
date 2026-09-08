from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, CheckConstraint, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CredentialStatusList(Base):
    """설계서 10. credential_status_lists"""

    __tablename__ = "credential_status_lists"
    __table_args__ = (
        CheckConstraint(
            "status_purpose IN ('REVOCATION', 'SUSPENSION')",
            name="ck_credential_status_lists_status_purpose",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    issuer_did: Mapped[str] = mapped_column(String(500), nullable=False)
    status_purpose: Mapped[str] = mapped_column(String(30), nullable=False)
    status_list_url: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    encoded_list: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="1")
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
