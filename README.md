# odysseus

Lightweight watcher that ingests Dorian DDoS Firewall payload tarballs into
the `versions` table consumed by the [`deploy_license`](../deploy_license)
API.

> For the end-to-end procedure that ties this watcher together with
> `deploy_license` to provision a new server, see
> [`deploy_license/WORKFLOW.md`](../deploy_license/WORKFLOW.md).

It polls an upload directory once a second, computes a SHA-256 over each new
payload tarball, renames the file to embed the digest, and inserts (or
upserts) a row into the shared MySQL `versions` table using the digest as the
row UUID.

---

## What it does

For every file under `DORIAN_UPLOAD_DIR` (default `/opt/dorian/uploads`) that
matches:

```
dorian-<body>-<MAJOR.MINOR.PATCH>-<os>-payload.tar.gz
```

Examples:

- `dorian-ddos-firewall-0.1.7-ubuntu-22.04-payload.tar.gz`
- `dorian-ddos-firewall-0.1.7-ubuntu-24.04-payload.tar.gz`

Legacy uploads without an OS segment are still accepted:

```
dorian-<body>-<MAJOR.MINOR.PATCH>-payload.tar.gz
```

the watcher will:

1. Compute `sha256` of the file contents.
2. Rename it in place to:

   ```
   dorian-<body>-<MAJOR.MINOR.PATCH>-<os>-payload-<sha256>.tar.gz
   ```

   (omit `<os>-` when the upload had no OS segment)
3. Upsert a row into `versions`:
   - `uuid`    — full hex SHA-256 digest
   - `version` — captured `MAJOR.MINOR.PATCH`
   - `os`      — OS label from the filename (e.g. `ubuntu-22.04`), or `NULL` for legacy names
   - `full_name` — the new filename (with hash suffix)
   - `path` — absolute path of the renamed file
   - `created` / `updated` — current timestamp (`updated` refreshed on conflict)

Files whose names already contain the `-<64 hex>.tar.gz` suffix are treated
as already-ingested and skipped. Anything else under the directory is
ignored.

If the database insert fails after a rename, the file is renamed back to its
original name so the next scan can retry cleanly.

---

## Requirements

- Python 3.8+
- MySQL/MariaDB reachable with the credentials below
- The `versions` table from
  [`deploy_license/schema.sql`](../deploy_license/schema.sql) must already
  exist in the target database (including the `os` column; run
  [`deploy_license/migrations/001_versions_os.sql`](../deploy_license/migrations/001_versions_os.sql)
  once if upgrading an older database)

Python deps (see `requirements.txt`):

- `pymysql >= 1.1.0`
- `python-dotenv >= 1.0.0`

---

## Installation

```bash
cd /home/odysseus
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Make sure the upload directory exists and is writable by the user that will
run the watcher (it needs to rename files in place):

```bash
sudo mkdir -p /opt/dorian/uploads
sudo chown "$USER" /opt/dorian/uploads
```

---

## Configuration

All configuration is via environment variables. A `.env` file in the
`odysseus` directory is loaded automatically, and as a convenience the
`.env` from a sibling `deploy_license/` checkout is also loaded (so both
services can share DB credentials).

| Variable             | Default                 | Description                          |
| -------------------- | ----------------------- | ------------------------------------ |
| `DORIAN_UPLOAD_DIR`  | `/opt/dorian/uploads`   | Directory to poll                    |
| `POLL_INTERVAL_SEC`  | `1`                     | Seconds between scans                |
| `LOG_LEVEL`          | `INFO`                  | Standard Python log level            |
| `DB_HOST`            | `127.0.0.1`             | MySQL host                           |
| `DB_PORT`            | `3306`                  | MySQL port                           |
| `DB_USER`            | `root`                  | MySQL user                           |
| `DB_PASSWORD`        | (empty)                 | MySQL password                       |
| `DB_NAME`            | `lic`                   | MySQL database                       |

---

## Running

Activate the venv and start the watcher in the foreground:

```bash
source venv/bin/activate
python watch_uploads.py
```

You should see something like:

```
2026-05-13 07:00:00,000 INFO watching /opt/dorian/uploads every 1.0s (DB 127.0.0.1/lic)
```

Drop a tarball into the upload directory:

```bash
cp dorian-ddos-firewall-0.1.2-payload.tar.gz /opt/dorian/uploads/
```

Within a second it will be renamed and recorded:

```
INFO hashed + renamed + recorded:
  dorian-ddos-firewall-0.1.2-payload.tar.gz
  -> dorian-ddos-firewall-0.1.2-payload-<sha256>.tar.gz
```

Stop with `Ctrl+C`.

### Run as a systemd service (optional)

Example unit (`/etc/systemd/system/odysseus.service`):

```ini
[Unit]
Description=Odysseus upload watcher
After=network.target mariadb.service

[Service]
Type=simple
WorkingDirectory=/home/odysseus
EnvironmentFile=/home/odysseus/.env
ExecStart=/home/odysseus/venv/bin/python /home/odysseus/watch_uploads.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now odysseus.service
sudo journalctl -u odysseus.service -f
```

---

## Project layout

```
odysseus/
├── watch_uploads.py    Main poll loop (rename + DB upsert)
├── requirements.txt    pymysql, python-dotenv
└── .gitignore          venv/, __pycache__/, .DS_Store
```

---

## Relationship to deploy_license

`odysseus` only writes to the `versions` table.
[`deploy_license`](../deploy_license) reads from it (via `GET /get_versions`)
and uses the recorded `path` when it uploads a Dorian tarball to a target
host. The two services should therefore point at the same database and the
`path` recorded by `odysseus` must be readable by the `deploy_license`
process.

---

## Troubleshooting

- **Nothing happens when I copy a file.** Confirm the filename matches the
  `dorian-<body>-<MAJOR.MINOR.PATCH>-payload.tar.gz` pattern exactly — case
  is insensitive but the `-payload.tar.gz` suffix and three-part version are
  required.
- **`watch dir missing` in debug logs.** `DORIAN_UPLOAD_DIR` does not exist
  or is not a directory. Create it (see Installation).
- **Database errors on every scan.** Check `DB_*` env vars and that the
  `versions` table from `deploy_license/schema.sql` has been created.
- **File renamed but no DB row.** The watcher renames back to the original
  name on DB failure; if you see a hashed filename without a row, check the
  `versions` unique key on `uuid` — a conflicting digest will upsert into
  the existing row by design.
