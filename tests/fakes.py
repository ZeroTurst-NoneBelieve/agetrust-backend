"""테스트용 가짜 DB 세션.

엔드포인트가 감사 로그(#9)를 기록하면서 `flush()`와 해시 체인 조회가
필요해졌다. 각 테스트 파일이 따로 가짜 세션을 두면 프로덕션 코드가 바뀔
때마다 여러 군데를 고쳐야 하므로 한 곳으로 모았다.
"""

from app.models import AuditLog, OutboxEvent


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
    """

    def __init__(self, rows=None, *, rowcount=0):
        self.rows = rows or {}
        self.added = []
        self.executed = []
        self.audit_logs = []
        self.outbox_events = []
        self.chain_tip = None
        self.commits = 0
        self.flushes = 0
        self._rowcount = rowcount
        self._next_id = 1000

    async def get(self, model, key):
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

    async def execute(self, statement, params=None):
        text = self._render(statement)

        # 감사 체인 append 구간을 직렬화하는 자문 잠금.
        if "pg_advisory_xact_lock" in text:
            return FakeResult()

        # 체인 tip 조회.
        if "FROM audit_logs" in text or "audit_logs.event_hash" in text:
            return FakeResult(scalar=self.chain_tip)

        self.executed.append(statement)
        return FakeResult(rowcount=self._rowcount)

    async def scalar(self, statement):
        return 0

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
