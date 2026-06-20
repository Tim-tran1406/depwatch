"""The DuckDB schema for stored scans.

Three tables form a small star schema: ``scans`` is the run, ``scored_packages``
is one row per package in that run (its signals and overall risk), and
``dimension_scores`` is the per-dimension breakdown at the finest grain. Summary
numbers (package counts, max risk) are not stored; they are computed in SQL so
there is a single source of truth.
"""

from __future__ import annotations

import duckdb

SCHEMA_STATEMENTS: tuple[str, ...] = (
    "CREATE SEQUENCE IF NOT EXISTS scan_id_seq START 1",
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id    BIGINT PRIMARY KEY DEFAULT nextval('scan_id_seq'),
        created_at TIMESTAMP NOT NULL,
        source     VARCHAR   NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scored_packages (
        scan_id                 BIGINT  NOT NULL REFERENCES scans(scan_id),
        name                    VARCHAR NOT NULL,
        version                 VARCHAR NOT NULL,
        is_direct               BOOLEAN NOT NULL,
        overall_risk            DOUBLE  NOT NULL,
        vulnerability_count     INTEGER NOT NULL,
        highest_severity        DOUBLE,
        days_since_last_release INTEGER,
        monthly_downloads       BIGINT  NOT NULL,
        contributor_count       INTEGER,
        license                 VARCHAR
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dimension_scores (
        scan_id   BIGINT  NOT NULL REFERENCES scans(scan_id),
        name      VARCHAR NOT NULL,
        dimension VARCHAR NOT NULL,
        score     DOUBLE  NOT NULL,
        reason    VARCHAR NOT NULL
    )
    """,
)


def apply_schema(con: duckdb.DuckDBPyConnection) -> None:
    """Create the tables if they do not already exist."""
    for statement in SCHEMA_STATEMENTS:
        con.execute(statement)
