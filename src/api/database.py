"""
Capa de Persistencia Desacoplada (Patrón Repository sobre SQLite WAL).

Diseño SOLID y Seguridad (AppSec):
- SRP: Encapsula exclusivamente el almacenamiento y consulta de flujos HTTP.
- DIP: Expone `FlowRepositoryProtocol` para que FastAPI no dependa de detalles SQL.
- Seguridad (CWE-89): Uso estricto de consultas parametrizadas (`?`) en el 100% de las sentencias.
- Optimización de RAM: Modo `WAL` con límite de caché de página acotado a 4 MB (`cache_size = -4000`).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional, Protocol

from src.domain.schemas import (
    HttpFlowCreate,
    HttpFlowRecord,
    SecurityAuditResult,
    TrafficStats,
)


class FlowRepositoryProtocol(Protocol):
    """Contrato abstracto de persistencia para inyección de dependencias."""

    def save_flow(self, flow: HttpFlowCreate) -> HttpFlowRecord:
        ...

    def list_flows(
        self,
        limit: int = 100,
        offset: int = 0,
        method: Optional[str] = None,
        host_filter: Optional[str] = None,
        min_status: Optional[int] = None,
    ) -> List[HttpFlowRecord]:
        ...

    def get_flow_by_id(self, flow_id: int) -> Optional[HttpFlowRecord]:
        ...

    def get_stats(self) -> TrafficStats:
        ...

    def clear_flows(self) -> int:
        ...


class SQLiteFlowRepository:
    """Implementación ligera y segura sobre SQLite3 nativo."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self._db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA cache_size=-4000;")  # Límite estricto ~4MB RAM
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS http_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    method TEXT NOT NULL,
                    scheme TEXT NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    url TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    content_type TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    request_size INTEGER NOT NULL,
                    response_size INTEGER NOT NULL,
                    request_headers_json TEXT NOT NULL,
                    response_headers_json TEXT NOT NULL,
                    request_preview TEXT NOT NULL,
                    response_preview TEXT NOT NULL,
                    security_audit_json TEXT NOT NULL,
                    security_grade TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON http_flows(id DESC);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_flows_host ON http_flows(host);"
            )

    def save_flow(self, flow: HttpFlowCreate) -> HttpFlowRecord:
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO http_flows (
                    method, scheme, host, path, url, status_code, content_type,
                    duration_ms, request_size, response_size,
                    request_headers_json, response_headers_json,
                    request_preview, response_preview,
                    security_audit_json, security_grade, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.method,
                    flow.scheme,
                    flow.host,
                    flow.path,
                    flow.url,
                    flow.status_code,
                    flow.content_type,
                    flow.duration_ms,
                    flow.request_size,
                    flow.response_size,
                    json.dumps(flow.request_headers, ensure_ascii=False),
                    json.dumps(flow.response_headers, ensure_ascii=False),
                    flow.request_preview,
                    flow.response_preview,
                    flow.security_audit.model_dump_json(),
                    flow.security_audit.grade,
                    flow.timestamp,
                ),
            )
            row_id = int(cursor.lastrowid or 1)
        return HttpFlowRecord(id=row_id, **flow.model_dump())

    def list_flows(
        self,
        limit: int = 100,
        offset: int = 0,
        method: Optional[str] = None,
        host_filter: Optional[str] = None,
        min_status: Optional[int] = None,
    ) -> List[HttpFlowRecord]:
        clauses: List[str] = []
        params: List[object] = []

        if method:
            clauses.append("UPPER(method) = UPPER(?)")
            params.append(method.strip())
        if host_filter:
            clauses.append("LOWER(host) LIKE LOWER(?)")
            params.append(f"%{host_filter.strip()}%")
        if min_status is not None:
            clauses.append("status_code >= ?")
            params.append(int(min_status))

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
            SELECT * FROM http_flows
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        params.extend([max(1, min(limit, 500)), max(0, offset)])

        with self._connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_flow_by_id(self, flow_id: int) -> Optional[HttpFlowRecord]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM http_flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def get_stats(self) -> TrafficStats:
        with self._connection() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_flows,
                    SUM(CASE WHEN LOWER(scheme) = 'https' THEN 1 ELSE 0 END) AS https_count,
                    SUM(CASE WHEN LOWER(scheme) = 'http' THEN 1 ELSE 0 END) AS http_count,
                    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS error_count,
                     COALESCE(AVG(duration_ms), 0.0) AS avg_duration_ms,
                    SUM(CASE WHEN security_grade IN ('D', 'F') THEN 1 ELSE 0 END) AS low_sec_count
                FROM http_flows
                """
            ).fetchone()

        if row is None or not row["total_flows"]:
            return TrafficStats()

        return TrafficStats(
            total_flows=int(row["total_flows"] or 0),
            https_count=int(row["https_count"] or 0),
            http_count=int(row["http_count"] or 0),
            error_count=int(row["error_count"] or 0),
            avg_duration_ms=round(float(row["avg_duration_ms"] or 0.0), 2),
            low_security_count=int(row["low_sec_count"] or 0),
        )

    def clear_flows(self) -> int:
        with self._connection() as conn:
            cursor = conn.execute("DELETE FROM http_flows")
            deleted = int(cursor.rowcount or 0)
        return deleted

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> HttpFlowRecord:
        return HttpFlowRecord(
            id=int(row["id"]),
            method=str(row["method"]),
            scheme=str(row["scheme"]),
            host=str(row["host"]),
            path=str(row["path"]),
            url=str(row["url"]),
            status_code=int(row["status_code"]),
            content_type=str(row["content_type"]),
            duration_ms=float(row["duration_ms"]),
            request_size=int(row["request_size"]),
            response_size=int(row["response_size"]),
            request_headers=json.loads(row["request_headers_json"]),
            response_headers=json.loads(row["response_headers_json"]),
            request_preview=str(row["request_preview"]),
            response_preview=str(row["response_preview"]),
            security_audit=SecurityAuditResult.model_validate_json(
                row["security_audit_json"]
            ),
            timestamp=str(row["timestamp"]),
        )
