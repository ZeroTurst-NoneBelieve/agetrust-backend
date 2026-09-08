"""align verification_logs with revised verification flow

개정된 검증 흐름(#31)을 반영한다.

키오스크가 nonce를 로컬에서 생성하고 백엔드를 호출하지 않으므로(mobile #7 K-1)
서버에 challenge 행이 생기지 않는다. verification_logs.challenge_id가 참조할
대상이 없어 결과 기록 INSERT 자체가 불가능한 상태였다.

- verification_challenges 삭제 (서버가 더 이상 챌린지를 발급하지 않음)
- verification_logs.challenge_id 제거
- verification_logs.kiosk_id 추가 (경유 테이블이 사라져 직접 필요.
  admin-web #3 매장별 감사 로그가 kiosks -> stores -> businesses로 JOIN)
- verification_logs.nonce_hash 추가 (설계서 §12의 "원문 대신 hash 저장" 원칙)
- (kiosk_id, nonce_hash) 복합 UNIQUE. mobile #17 K-7의 로컬 큐잉 재시도로 같은
  결과가 두 번 전송되는 것을 DB 차원에서 막는다. 전역 UNIQUE로 걸면 서로 다른
  키오스크가 우연히 같은 nonce를 만들었을 때 뒤에 온 정상 인증이 영구 거부되어
  감사 로그에서 사라진다
- verification_logs.transport_type 추가 (삭제되는 테이블에서 갈 곳이 없어진
  컬럼. 값은 2채널 조합이라 'QR_BLE', ADR-0003)
- verification_logs.received_at / is_late 추가 (ADR-0011. 키오스크 시계를 믿지
  않기 위해 서버 수신 시각을 함께 남기고, 7일 초과 지연을 버리지 않고 표시)
- verification_logs.status_list_age_seconds 추가 (ADR-0013. 판정에 쓴
  StatusList 캐시 나이. 캐시를 쓰지 않은 판정에는 값이 없어 NULL 허용)
- verification_logs.result_status의 정상값을 'SUCCESS' -> 'PASS'로 변경.
  ADR-0011이 결과 기록 API 본문을 "result_status": "PASS"로 확정했다. 값의
  출처가 키오스크이고 키오스크는 같은 판정을 BLE status_notify 0x20 PASS로
  폰에 먼저 보내므로(transport-protocol §5.7), 경계마다 이름이 갈리지 않도록
  DB도 계약에 맞춘다. adult_verifications.result_status의 'SUCCESS'는 서버가
  직접 판정하는 다른 테이블이라 그대로 둔다

결과 기록 API(ADR-0011)가 아직 없어 이 시점에는 테이블이 비어 있다. API가
생긴 뒤에 컬럼을 더하면 기존 행을 어떻게 채울지 정해야 하므로, 같은 리비전에
함께 넣는다.

두 테이블 모두 이 시점까지 어떤 코드 경로에서도 INSERT된 적이 없다
(키오스크 검증 결과 기록 API가 아직 없음). 따라서 NOT NULL 컬럼을 기본값
없이 추가한다. 만약 수동으로 넣은 행이 있다면 이 마이그레이션은 실패하는데,
데이터를 조용히 지우는 것보다 실패해서 확인하게 하는 편이 낫다.

Revision ID: d4f8a2b16c07
Revises: 69dc2d9f707c
Create Date: 2026-08-26 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd4f8a2b16c07'
down_revision = '69dc2d9f707c'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # challenge_id를 먼저 없앤다. verification_challenges를 참조하는 FK가
    # 이 컬럼에 걸려 있어, 컬럼을 지우기 전에는 테이블을 DROP할 수 없다.
    # (컬럼을 지우면 딸린 FK/UNIQUE 제약도 함께 사라진다)
    op.drop_column('verification_logs', 'challenge_id')

    op.add_column(
        'verification_logs',
        sa.Column('kiosk_id', sa.BigInteger(), nullable=False),
    )
    op.create_foreign_key(
        None, 'verification_logs', 'kiosks', ['kiosk_id'], ['id']
    )

    op.add_column(
        'verification_logs',
        sa.Column('nonce_hash', sa.String(length=128), nullable=False),
    )
    # kiosk_id가 선두인 btree 인덱스가 이 제약에 딸려 온다.
    # admin-web #3의 kiosks -> stores -> businesses 조회 경로가 이를 탄다.
    op.create_unique_constraint(
        'uq_verification_logs_kiosk_nonce',
        'verification_logs',
        ['kiosk_id', 'nonce_hash'],
    )

    # ADR-0011 결과 기록 API 계약 / ADR-0013 StatusList 캐시 추적
    op.add_column(
        'verification_logs',
        sa.Column('transport_type', sa.String(length=20), nullable=False),
    )
    op.create_check_constraint(
        'ck_verification_logs_transport_type',
        'verification_logs',
        "transport_type IN ('QR_BLE')",
    )
    op.add_column(
        'verification_logs',
        sa.Column(
            'received_at',
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
    )
    op.add_column(
        'verification_logs',
        sa.Column('is_late', sa.Boolean(), server_default='false', nullable=False),
    )
    op.add_column(
        'verification_logs',
        sa.Column('status_list_age_seconds', sa.Integer(), nullable=True),
    )

    # 정상값 'SUCCESS' -> 'PASS' (ADR-0011 결과 기록 API 계약).
    # CHECK는 69dc2d9f707c가 만든 것이라 여기서 지우고 다시 만든다.
    # 이 테이블은 아직 비어 있어 기존 행을 옮길 UPDATE가 필요 없다.
    op.drop_constraint(
        'ck_verification_logs_result_status', 'verification_logs', type_='check'
    )
    op.create_check_constraint(
        'ck_verification_logs_result_status',
        'verification_logs',
        "result_status IN ("
        "'PASS', 'FAIL_EXPIRED', 'FAIL_FACE_MISMATCH', 'FAIL_INVALID_VC', "
        "'FAIL_INVALID_VP', 'FAIL_REVOKED_VC', 'FAIL_CHALLENGE', 'INTERNAL_ERROR'"
        ")",
    )

    op.drop_table('verification_challenges')


def downgrade() -> None:
    op.create_table(
        'verification_challenges',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('kiosk_id', sa.BigInteger(), nullable=False),
        sa.Column('transport_type', sa.String(length=20), nullable=False),
        sa.Column('challenge_hash', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=30), server_default='PENDING', nullable=False),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING', 'CONSUMED', 'EXPIRED', 'CANCELLED')",
            name='ck_verification_challenges_status',
        ),
        sa.CheckConstraint(
            "transport_type IN ('QR', 'NFC', 'BLE')",
            name='ck_verification_challenges_transport_type',
        ),
        sa.ForeignKeyConstraint(['kiosk_id'], ['kiosks.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('challenge_hash'),
    )

    op.drop_constraint(
        'ck_verification_logs_result_status', 'verification_logs', type_='check'
    )
    op.create_check_constraint(
        'ck_verification_logs_result_status',
        'verification_logs',
        "result_status IN ("
        "'SUCCESS', 'FAIL_EXPIRED', 'FAIL_FACE_MISMATCH', 'FAIL_INVALID_VC', "
        "'FAIL_INVALID_VP', 'FAIL_REVOKED_VC', 'FAIL_CHALLENGE', 'INTERNAL_ERROR'"
        ")",
    )

    op.drop_column('verification_logs', 'status_list_age_seconds')
    op.drop_column('verification_logs', 'is_late')
    op.drop_column('verification_logs', 'received_at')
    # CHECK 제약도 컬럼과 함께 사라진다
    op.drop_column('verification_logs', 'transport_type')

    # 복합 UNIQUE는 컬럼과 함께 사라진다
    op.drop_column('verification_logs', 'nonce_hash')
    op.drop_column('verification_logs', 'kiosk_id')

    op.add_column(
        'verification_logs',
        sa.Column('challenge_id', sa.BigInteger(), nullable=False),
    )
    op.create_foreign_key(
        None, 'verification_logs', 'verification_challenges', ['challenge_id'], ['id']
    )
    op.create_unique_constraint(None, 'verification_logs', ['challenge_id'])
