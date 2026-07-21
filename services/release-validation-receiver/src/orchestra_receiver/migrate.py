from __future__ import annotations

import argparse
import hashlib
import os
from importlib.resources import files

import psycopg


def apply_migrations(database_url: str) -> None:
    migration = (
        files("orchestra_receiver")
        .joinpath("migrations", "001_receiver.sql")
        .read_text(encoding="utf-8")
    )
    digest = f"sha256:{hashlib.sha256(migration.encode('utf-8')).hexdigest()}"
    with psycopg.connect(database_url, autocommit=False) as connection:
        with connection.transaction():
            connection.execute("SELECT pg_advisory_xact_lock(734726541621)")
            connection.execute("CREATE SCHEMA IF NOT EXISTS orchestra_lab_receiver")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS orchestra_lab_receiver.schema_migrations (
                  version integer PRIMARY KEY,
                  script_digest text NOT NULL CHECK (
                    script_digest ~ '^sha256:[0-9a-f]{64}$'
                  ),
                  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
                )
                """
            )
            existing = connection.execute(
                """
                SELECT script_digest
                FROM orchestra_lab_receiver.schema_migrations
                WHERE version = 1
                """
            ).fetchone()
            if existing:
                if existing[0] != digest:
                    raise RuntimeError("receiver migration 1 digest does not match")
                return
            connection.execute(migration)
            connection.execute(
                """
                INSERT INTO orchestra_lab_receiver.schema_migrations (version, script_digest)
                VALUES (1, %s)
                """,
                (digest,),
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database-url", default=os.environ.get("RECEIVER_DATABASE_URL")
    )
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or RECEIVER_DATABASE_URL is required")
    apply_migrations(args.database_url)


if __name__ == "__main__":
    main()
