"""테스트용 가짜 DB 세션.

엔드포인트가 감사 로그(#9)를 기록하면서 `flush()`와 해시 체인 조회가
필요해졌다. 각 테스트 파일이 따로 가짜 세션을 두면 프로덕션 코드가 바뀔
때마다 여러 군데를 고쳐야 하므로 한 곳으로 모았다.
"""

from app.models import AuditLog, OutboxEvent

# "주입된 값이 없음"과 "주입된 값이 None"을 구분하기 위한 표식.
_MISSING = object()


class FakeResult:
    def __init__(self, rows=None, rowcount=0, scalar=None):
        self._rows = list(rows or [])
        self.rowcount = rowcount
        self._scalar = scalar

    def scalar_one_or_none(self):
        return self._scalar

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class FakeDb:
    """SQLAlchemy AsyncSession의 최소 대역.

    - `executed`      : 업무 로직이 실행한 statement (감사 인프라 쿼리는 제외)
    - `audit_logs`    : 기록된 AuditLog 행
    - `outbox_events` : 기록된 OutboxEvent 행
    - `chain_tip`     : 마지막 AuditLog의 event_hash (해시 체인 tip)

    select 결과는 두 갈래로 준다.

    - `scalar_results` : {모델: 돌려줄 값}. select(Model) 형태의 조회에 쓴다.
    - `scalar_default` : 위에 걸리지 않는 집계 쿼리(MAX+1 등)의 반환값.
    - `returning_rows` : UPDATE ... RETURNING이 돌려줄 행.
    """

    def __init__(
        self,
        rows=None,
        *,
        rowcount=0,
        scalar_results=None,
        scalar_default=0,
        returning_rows=None,
    ):
        self.rows = rows or {}
        self.scalar_results = scalar_results or {}
        # 엔티티 대역이 걸리지 않는 집계 쿼리(MAX+1, COUNT 등)의 기본 반환값.
        self.scalar_default = scalar_default
        # UPDATE ... RETURNING이 돌려줄 행. 폐기된 VC의 상태 목록 배정을
        # 흉내내는 데 쓴다.
        self.returning_rows = list(returning_rows or [])
        self.scalar_query_hits = {}
        self.added = []
        self.executed = []
        self.audit_logs = []
        self.outbox_events = []
        self.chain_tip = None
        self.commits = 0
        self.flushes = 0
        self.get_calls = []
        self._rowcount = rowcount
        self._next_id = 1000

    async def get(self, model, key, **kwargs):
        self.get_calls.append((model, key, kwargs))
        return self.rows.get((model, key))

    def add(self, row):
        self.added.append(row)
        if isinstance(row, AuditLog):
            self.audit_logs.append(row)
            self.chain_tip = row.event_hash
        elif isinstance(row, OutboxEvent):
            self.outbox_events.append(row)

    async def flush(self):
        """INSERT 후 PK가 채워지는 것을 흉내낸다."""
        self.flushes += 1
        for row in self.added:
            if getattr(row, "id", None) is None:
                row.id = self._next_id
                self._next_id += 1

    @staticmethod
    def _selected_entities(statement):
        """select(Model) 형태로 조회하는 엔티티만 골라낸다.

        select(func.max(Model.col))처럼 컬럼을 가공하는 쿼리도
        column_descriptions에 entity가 붙어 나온다. 이 둘을 구분하지 않으면
        집계 쿼리에 엔티티 대역이 잘못 주입된다. expr이 엔티티 자신일 때만
        "행을 통째로 가져오는 조회"로 본다.
        """
        return {
            description["entity"]
            for description in getattr(statement, "column_descriptions", [])
            if description.get("entity") is not None
            and description.get("expr") is description["entity"]
        }

    def _injected_scalar(self, statement):
        """statement가 대역을 주입해 둔 엔티티를 향하면 그 값을 돌려준다.

        렌더된 SQL 문자열이 아니라 ORM 엔티티로 판단하므로, 쿼리 포맷이
        바뀌어도 의도한 대역이 그대로 동작한다.
        찾지 못하면 _MISSING을 돌려주어 "주입값 없음"과 "주입값이 None"을
        구분한다.
        """
        entities = self._selected_entities(statement)
        for entity, scalar_result in self.scalar_results.items():
            if entity in entities:
                self.scalar_query_hits[entity] = self.scalar_query_hits.get(entity, 0) + 1
                return scalar_result
        return _MISSING

    async def execute(self, statement, params=None):
        text = self._render(statement)

        # select(Model) 결과를 ORM 엔티티 기준으로 주입한다.
        injected = self._injected_scalar(statement)
        if injected is not _MISSING:
            return FakeResult(scalar=injected)

        # 감사 체인 append 구간과 상태 목록 배정 구간을 직렬화하는 자문 잠금.
        if "pg_advisory_xact_lock" in text:
            return FakeResult()

        # 체인 tip 조회.
        if "FROM audit_logs" in text or "audit_logs.event_hash" in text:
            return FakeResult(scalar=self.chain_tip)

        self.executed.append(statement)
        if "RETURNING" in text.upper():
            return FakeResult(
                rows=self.returning_rows, rowcount=len(self.returning_rows)
            )
        return FakeResult(rowcount=self._rowcount)

    async def scalar(self, statement):
        """execute()와 같은 규칙으로 주입값을 돌려준다.

        select(Model)은 주입된 엔티티 대역을, 집계 쿼리(MAX+1 등)는
        scalar_default를 돌려준다. 예전에는 무조건 0을 돌려주었는데,
        엔티티를 기대하는 호출에도 0이 넘어가 프로덕션 코드가 정수에
        속성 접근을 시도하다 터졌다.
        """
        injected = self._injected_scalar(statement)
        if injected is not _MISSING:
            return injected
        if self._selected_entities(statement):
            # 대역을 주지 않은 엔티티 조회는 "행이 없음"으로 본다.
            return None
        return self.scalar_default

    async def commit(self):
        self.commits += 1

    async def refresh(self, row):
        return None

    def statements_touching(self, table):
        """특정 테이블을 건드린 업무 statement만 골라낸다."""
        return [s for s in self.executed if table in self._render(s)]

    @staticmethod
    def _render(statement):
        try:
            return str(statement.compile(compile_kwargs={"literal_binds": True}))
        except Exception:
            return str(statement)


# ---------------------------------------------------------------------------
# Outbox → Kafka Publisher (#9) 대역
# ---------------------------------------------------------------------------
class FakeRecordMetadata:
    """aiokafka가 send_and_wait에서 돌려주는 RecordMetadata의 최소 대역."""

    def __init__(self, topic, partition, offset):
        self.topic = topic
        self.partition = partition
        self.offset = offset


class FakeProducer:
    """AIOKafkaProducer의 최소 대역.

    `fail_with`를 주면 전송이 그 예외로 실패한다. 브로커가 죽었을 때의
    동작을 검증하기 위한 것이다.
    """

    def __init__(self, *, fail_with=None, fail_after=0, topic="agetrust.audit-events"):
        self.sent = []
        self.fail_with = fail_with
        # 앞의 몇 건은 성공시킨 뒤 실패시킨다. 배치 중간에 브로커가 죽는 상황.
        self.fail_after = fail_after
        self.topic = topic
        self.started = False
        self.stopped = False
        self._offset = 0

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def send_and_wait(self, topic, *, value, key):
        if self.fail_with is not None and len(self.sent) >= self.fail_after:
            raise self.fail_with
        self.sent.append({"topic": topic, "key": key, "value": value})
        metadata = FakeRecordMetadata(topic, 0, self._offset)
        self._offset += 1
        return metadata


class FakeOutboxDb:
    """Publisher가 쓰는 만큼만 흉내낸 세션.

    - `pending`   : _claim_pending이 집어갈 미발행 이벤트
    - `backfills` : audit_logs에 Kafka 좌표를 되채운 UPDATE 문
    """

    def __init__(self, pending=None, *, backfill_error=None, exhausted_count=0):
        self.pending = list(pending or [])
        self.backfills = []
        self.commits = 0
        self.selects = []
        self.savepoints = 0
        # 좌표 기록이 유니크 제약에 걸리는 상황을 재현하기 위한 것.
        self.backfill_error = backfill_error
        # count_exhausted()가 돌려줄 값.
        self.exhausted_count = exhausted_count

    async def scalar(self, statement):
        return self.exhausted_count

    async def execute(self, statement, params=None):
        text = str(statement)
        if text.lstrip().upper().startswith("UPDATE AUDIT_LOGS"):
            if self.backfill_error is not None:
                raise self.backfill_error
            self.backfills.append(statement)
            return FakeResult()
        self.selects.append(statement)
        return FakeResult(rows=self.pending)

    def begin_nested(self):
        """SAVEPOINT 대역. 안에서 터진 예외는 밖으로 그대로 올려보낸다."""
        self.savepoints += 1
        return _FakeSavepoint()

    async def commit(self):
        self.commits += 1


class _FakeSavepoint:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        # 롤백만 하고 예외는 삼키지 않는다 (실제 SAVEPOINT와 같은 동작).
        return False
    