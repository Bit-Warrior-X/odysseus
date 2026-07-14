#!/usr/bin/env python3
"""
Poll /opt/dorian/uploads every second for dorian payload tarballs.

Files like:
  dorian-ddos-firewall-0.1.7-ubuntu-22.04-payload.tar.gz
  dorian-ddos-firewall-0.1.7-ubuntu-24.04-payload.tar.gz

Legacy (no OS segment):
  dorian-ddos-firewall-0.1.2-payload.tar.gz

Plain uploads are renamed to embed a SHA-256 digest before -payload:
  dorian-ddos-firewall-0.1.7-ubuntu-22.04-payload-<sha256>.tar.gz

Pre-hashed uploads are also registered. The content hash is always computed
from the file; a wrong placeholder hash in the filename is corrected on rename.

Rows are upserted into `versions` keyed by (version, os); uuid is the file
content SHA-256 hex digest.
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
from typing import Any, Optional

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
        user=os.environ.get("DB_USER", "dorian"),
        password=os.environ.get("DB_PASSWORD", "StrongPassword123!"),
        database=os.environ.get("DB_NAME", "lic"),
        autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )


def version_row_for(
    conn, version: str, os_label: Optional[str]
) -> Optional[dict[str, Any]]:
    with conn.cursor() as cur:
        if os_label:
            cur.execute(
                "SELECT id, uuid, path FROM versions WHERE version = %s AND os = %s LIMIT 1",
                (version, os_label),
            )
        else:
            cur.execute(
                "SELECT id, uuid, path FROM versions WHERE version = %s AND os IS NULL LIMIT 1",
                (version,),
            )
        return cur.fetchone()


def needs_registration(
    conn,
    *,
    version: str,
    os_label: Optional[str],
    file_path: str,
    digest_hex: str,
) -> bool:
    row = version_row_for(conn, version, os_label)
    if row is None:
        return True
    return row.get("path") != file_path or row.get("uuid") != digest_hex


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
        "uuid = VALUES(uuid), "
        "full_name = VALUES(full_name), "
        "path = VALUES(path), "
        "updated = CURRENT_TIMESTAMP"
    )
    with conn.cursor() as cur:
        cur.execute(sql, (digest_hex, version, os_label, full_name, file_path))


def hashed_filename(name: str, digest: str) -> str:
    if RE_HASHED.match(name):
        return re.sub(
            r"-payload-[a-f0-9]{64}\.tar\.gz$",
            rf"-payload-{digest}.tar.gz",
            name,
            flags=re.IGNORECASE,
        )
    return re.sub(
        r"(-payload)\.tar\.gz$",
        rf"\1-{digest}.tar.gz",
        name,
        flags=re.IGNORECASE,
    )


def ensure_hashed_path(path: Path, digest: str) -> Path:
    new_name = hashed_filename(path.name, digest)
    if new_name == path.name:
        return path

    new_path = path.parent / new_name
    if new_path.exists() and new_path.resolve() != path.resolve():
        LOG.warning("target already exists, using existing file: %s", new_path)
        return new_path

    old_name = path.name
    path.rename(new_path)
    LOG.info("renamed to content hash: %s -> %s", old_name, new_name)
    return new_path


def register_tarball(path: Path) -> None:
    parsed = parse_tarball_name(path.name)
    if not parsed:
        return

    digest = sha256_file(path)
    final_path = ensure_hashed_path(path, digest)
    resolved = str(final_path.resolve())

    conn = db_connect()
    try:
        if not needs_registration(
            conn,
            version=parsed.version,
            os_label=parsed.os_label,
            file_path=resolved,
            digest_hex=digest,
        ):
            return

        insert_version(
            conn,
            digest_hex=digest,
            version=parsed.version,
            os_label=parsed.os_label,
            full_name=final_path.name,
            file_path=resolved,
        )
    finally:
        conn.close()

    LOG.info(
        "recorded: %s (version=%s os=%s uuid=%s)",
        final_path.name,
        parsed.version,
        parsed.os_label or "—",
        digest[:12] + "…",
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

        if not (RE_PLAIN.match(path.name) or RE_HASHED.match(path.name)):
            LOG.debug("ignored (pattern): %s", path.name)
            continue

        try:
            register_tarball(path)
        except OSError as e:
            LOG.error("failed processing %s: %s", path, e)
        except pymysql.MySQLError as e:
            LOG.error("database error for %s: %s", path, e)


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
