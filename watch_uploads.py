#!/usr/bin/env python3
"""
Poll /opt/dorian/uploads every second for dorian payload tarballs.

Files like: dorian-ddos-firewall-0.1.2-payload.tar.gz
are renamed to: dorian-ddos-firewall-0.1.2-payload-<sha256>.tar.gz
and a row is inserted into the `versions` table (uuid = full hex digest).

Files whose names already include the content hash are skipped for DB writes.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
import time
from pathlib import Path

import pymysql

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

WATCH_DIR = Path(os.environ.get("DORIAN_UPLOAD_DIR", "/opt/dorian/uploads"))
POLL_INTERVAL_SEC = float(os.environ.get("POLL_INTERVAL_SEC", "1"))

# dorian-<anything>-<semver>-payload.tar.gz  OR  ...-payload-<64 hex sha256>.tar.gz
RE_PLAIN = re.compile(
    r"^dorian-(?P<body>.+)-(?P<ver>\d+\.\d+\.\d+)-payload\.tar\.gz$",
    re.IGNORECASE,
)
RE_HASHED = re.compile(
    r"^dorian-(?P<body>.+)-(?P<ver>\d+\.\d+\.\d+)-payload-(?P<hash>[a-f0-9]{64})\.tar\.gz$",
    re.IGNORECASE,
)

LOG = logging.getLogger("watch_uploads")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def db_connect():
    return pymysql.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", ""),
        database=os.environ.get("DB_NAME", "lic"),
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )


def insert_version(conn, *, digest_hex: str, version: str, full_name: str, file_path: str) -> None:
    sql = (
        "INSERT INTO versions (uuid, version, full_name, path, created, updated) "
        "VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
        "ON DUPLICATE KEY UPDATE "
        "full_name = VALUES(full_name), path = VALUES(path), updated = CURRENT_TIMESTAMP"
    )
    with conn.cursor() as cur:
        cur.execute(sql, (digest_hex, version, full_name, file_path))


def process_plain_file(path: Path) -> None:
    m = RE_PLAIN.match(path.name)
    if not m:
        return
    version = m.group("ver")
    old_name = path.name

    digest = sha256_file(path)
    new_name = re.sub(
        r"(-payload)\.tar\.gz$",
        rf"\1-{digest}.tar.gz",
        path.name,
        flags=re.IGNORECASE,
    )
    new_path = path.parent / new_name
    if new_path.exists() and new_path != path:
        LOG.warning("target already exists, skipping rename: %s", new_path)
        return

    path.rename(new_path)
    try:
        conn = db_connect()
        try:
            insert_version(
                conn,
                digest_hex=digest,
                version=version,
                full_name=new_name,
                file_path=str(new_path.resolve()),
            )
        finally:
            conn.close()
    except pymysql.MySQLError:
        new_path.rename(path)
        raise

    LOG.info("hashed + renamed + recorded: %s -> %s", old_name, new_name)


def scan_once() -> None:
    if not WATCH_DIR.is_dir():
        LOG.debug("watch dir missing: %s", WATCH_DIR)
        return

    for path in sorted(WATCH_DIR.iterdir()):
        if not path.is_file():
            continue
        if not path.name.lower().endswith(".tar.gz"):
            continue

        if RE_HASHED.match(path.name):
            # Filename already carries the content hash suffix; do not insert again.
            continue

        if RE_PLAIN.match(path.name):
            try:
                process_plain_file(path)
            except OSError as e:
                LOG.error("failed processing %s: %s", path, e)
            except pymysql.MySQLError as e:
                LOG.error("database error for %s: %s", path, e)
            continue

        # Other tar.gz files under the directory are ignored.
        LOG.debug("ignored (pattern): %s", path.name)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if load_dotenv:
        here = Path(__file__).resolve().parent
        load_dotenv(here / ".env")
        load_dotenv(here.parent / "deploy_license" / ".env")

    LOG.info(
        "watching %s every %ss (DB %s/%s)",
        WATCH_DIR,
        POLL_INTERVAL_SEC,
        os.environ.get("DB_HOST", "127.0.0.1"),
        os.environ.get("DB_NAME", "lic"),
    )

    while True:
        try:
            scan_once()
        except Exception:
            LOG.exception("scan loop error")
        time.sleep(POLL_INTERVAL_SEC)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        LOG.info("stopped")
        sys.exit(0)
