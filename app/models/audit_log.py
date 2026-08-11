import uuid
from datetime import datetime

from sqlalchemy import (
    TIMESTAMP,
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AuditLog(Base):
    """설계서 15. audit_logs

    source_kiosk_id로 kiosks -> stores -> businesses를 추적한다.
    Kafka만을 영구 불변 원장으로 간주하지 않고 hash chain + 별도 immutable storage를 결합한다.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        UniqueConstraint(
            "kafka_topic", "kafka_partition", "kafka_offset", name="uq_audit_logs_kafka_position"
        ),
        CheckConstraint(
            "actor_type IN ('USER', 'ADMIN', 'KIOSK', 'SYSTEM')",
            name="ck_audit_logs_actor_type",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(30), nullable=False)
    actor_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_kiosk_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("kiosks.id"), nullable=True)
    aggregate_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    aggregate_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    kafka_topic: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kafka_partition: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kafka_offset: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    previous_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    archive_object_key: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    archive_object_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
