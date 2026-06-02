#!/usr/bin/env python3
"""
Poll /opt/dorian/uploads every second for dorian payload tarballs.

Files like:
  dorian-ddos-firewall-0.1.7-ubuntu-22.04-payload.tar.gz
  dorian-ddos-firewall-0.1.7-ubuntu-24.04-payload.tar.gz

Legacy (no OS segment):
  dorian-ddos-firewall-0.1.2-payload.tar.gz

are renamed to embed a SHA-256 digest before -payload:
  dorian-ddos-firewall-0.1.7-ubuntu-22.04-payload-<sha256>.tar.gz

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
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pymysql

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

WATCH_DIR = Path(os.environ.get("DORIAN_UPLOAD_DIR", "/opt/dorian/uploads"))
POLL_INTERVAL_SEC = float(os.environ.get("POLL_INTERVAL_SEC", "1"))

# Optional OS segment: ubuntu-22.04, ubuntu-24.04, etc.
_OS_SEGMENT = r"(?:-(?P<os>[a-z][a-z0-9]*-\d+(?:\.\d+)+))?"
_RE_VER = r"(?P<ver>\d+\.\d+\.\d+)"

RE_PLAIN = re.compile(
    rf"^dorian-(?P<body>.+)-{_RE_VER}{_OS_SEGMENT}-payload\.tar\.gz$",
    re.IGNORECASE,
)
RE_HASHED = re.compile(
    rf"^dorian-(?P<body>.+)-{_RE_VER}{_OS_SEGMENT}-payload-(?P<hash>[a-f0-9]{{64}})\.tar\.gz$",
    re.IGNORECASE,
)

LOG = logging.getLogger("watch_uploads")


@dataclass(frozen=True)
class ParsedTarball:
    version: str
    os_label: Optional[str]


def parse_tarball_name(name: str) -> Optional[ParsedTarball]:
    m = RE_HASHED.match(name) or RE_PLAIN.match(name)
    if not m:
        return None
    os_raw = m.groupdict().get("os")
    os_label = os_raw.strip().lower() if os_raw else None
    return ParsedTarball(version=m.group("ver"), os_label=os_label or None)


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


def insert_version(
    conn,
    *,
    digest_hex: str,
    version: str,
    os_label: Optional[str],
    full_name: str,
    file_path: str,
) -> None:
    sql = (
        "INSERT INTO versions (uuid, version, os, full_name, path, created, updated) "
        "VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
        "ON DUPLICATE KEY UPDATE "
        "version = VALUES(version), "
        "os = VALUES(os), "
        "full_name = VALUES(full_name), "
        "path = VALUES(path), "
        "updated = CURRENT_TIMESTAMP"
    )
    with conn.cursor() as cur:
        cur.execute(sql, (digest_hex, version, os_label, full_name, file_path))


def process_plain_file(path: Path) -> None:
    parsed = parse_tarball_name(path.name)
    if not parsed:
        return
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
                version=parsed.version,
                os_label=parsed.os_label,
                full_name=new_name,
                file_path=str(new_path.resolve()),
            )
        finally:
            conn.close()
    except pymysql.MySQLError:
        new_path.rename(path)
        raise

    LOG.info(
        "hashed + renamed + recorded: %s -> %s (version=%s os=%s)",
        old_name,
        new_name,
        parsed.version,
        parsed.os_label or "—",
    )


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
            continue

        if RE_PLAIN.match(path.name):
            try:
                process_plain_file(path)
            except OSError as e:
                LOG.error("failed processing %s: %s", path, e)
            except pymysql.MySQLError as e:
                LOG.error("database error for %s: %s", path, e)
            continue

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
