import datetime
import logging
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from sqlalchemy.orm import Session

from api.auth import get_current_user
from database import get_db
from models import User
from services.postgres_cli import parse_database_url

router = APIRouter()
logger = logging.getLogger(__name__)

BACKUP_DIR = "/app/backups"
DATABASE_URL = os.getenv("DATABASE_URL", "")
RESTORE_CHUNK_SIZE = 1024 * 1024
BACKUP_GROUPS = {
    "collection": [
        "collection",
        "wishlist",
        "binders",
        "binder_cards",
        "printing_detail_tags",
        "collection_printing_detail_tags",
    ],
    "users": ["users", "user_settings", "settings", "printing_detail_tags"],
    "cards": ["cards", "sets", "price_history", "custom_card_matches"],
    "products": [
        "product_purchases",
        "product_cards",
        "product_ledger_entries",
        "portfolio_snapshots",
        "printing_detail_tags",
        "product_card_printing_detail_tags",
        "product_ledger_printing_detail_tags",
    ],
    "system": ["sync_log"],
    "images": ["image_cache"],
}


def get_db_params():
    """Parse DATABASE_URL into pg params."""
    return parse_database_url(DATABASE_URL)


class UnsafeRestoreError(ValueError):
    """The uploaded SQL contains statements a restore must never run."""


# pg_dump >= 16.10/17.6/18 frames plain dumps with these psql meta-commands. They
# are removed and replaced by a server-chosen key so the dump cannot leave
# restricted mode.
_DUMP_RESTRICT_LINE = re.compile(rb"^\\(?:un)?restrict [A-Za-z0-9]+\r?\n?$")
_COPY_FROM_STDIN = re.compile(rb"^COPY .+ FROM stdin;\r?\n?$")
_COPY_DATA_END = re.compile(rb"^\\\.\r?\n?$")
_WORD = re.compile(rb"[A-Za-z_]+")
# Best-effort guard for COPY ... PROGRAM hidden in what looks like COPY data.
_INLINE_COPY_PROGRAM = re.compile(rb"\bCOPY\b.*\bPROGRAM\s*(?:E?')", re.IGNORECASE)


def _sanitize_restore_file(source: Path, destination: Path) -> None:
    """Write a psql script that cannot run psql meta-commands or server programs.

    psql executes backslash meta-commands such as ``\\!`` (run a shell command)
    anywhere in a script, so an uploaded "backup" could otherwise execute code in
    the backend container. The sanitized script starts with ``\\restrict`` using
    a random key: psql then rejects every meta-command except ``\\unrestrict``
    with that unguessable key. ``COPY ... PROGRAM`` runs a command on the
    database server and is never produced by pg_dump, so it is rejected outright.
    """
    restrict_key = secrets.token_hex(16).encode()
    in_copy_data = False
    statement_has_copy = False
    with source.open("rb") as raw, destination.open("wb") as out:
        out.write(b"\\restrict " + restrict_key + b"\n")
        for line in raw:
            if in_copy_data:
                if _INLINE_COPY_PROGRAM.search(line):
                    raise UnsafeRestoreError("COPY ... PROGRAM is not allowed in a restore")
                out.write(line)
                if _COPY_DATA_END.match(line):
                    in_copy_data = False
                continue
            if _DUMP_RESTRICT_LINE.match(line.strip() + b"\n"):
                continue
            for word in _WORD.findall(line):
                upper = word.upper()
                if upper == b"COPY":
                    statement_has_copy = True
                elif upper == b"PROGRAM" and statement_has_copy:
                    raise UnsafeRestoreError("COPY ... PROGRAM is not allowed in a restore")
            if _COPY_FROM_STDIN.match(line):
                in_copy_data = True
            if b";" in line:
                statement_has_copy = False
            out.write(line)
        if not in_copy_data:
            out.write(b"\n")
        out.write(b"\\unrestrict " + restrict_key + b"\n")


def _remove_file(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        logger.warning("Could not remove temporary backup file %s", path, exc_info=True)


@router.get("/download")
def download_backup(
    include: str = Query(
        default="full",
        description="Comma-separated: full,collection,users,cards,products,images",
    ),
    current_user: User = Depends(get_current_user),
):
    """Create and download a PostgreSQL dump."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    params = get_db_params()
    if not params:
        raise HTTPException(status_code=500, detail="Database URL not configured")

    groups = [group.strip() for group in include.split(",") if group.strip()]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pokemon_tcg_backup_{timestamp}.sql"
    filepath = os.path.join(BACKUP_DIR, filename)

    env = os.environ.copy()
    env["PGPASSWORD"] = params["password"]

    cmd = [
        "pg_dump",
        "-h", params["host"],
        "-p", params["port"],
        "-U", params["user"],
        "-d", params["dbname"],
        "-f", filepath,
        "--clean",
        "--if-exists",
    ]

    if "full" in groups:
        if "images" not in groups:
            # Keep the cache schema and its owned sequence, but omit the large cache rows.
            cmd.extend(["--exclude-table-data", "image_cache"])
    else:
        tables = []
        for group in groups:
            if group in BACKUP_GROUPS:
                tables.extend(BACKUP_GROUPS[group])
        tables = list(dict.fromkeys(tables))
        if not tables:
            raise HTTPException(status_code=400, detail="No valid backup groups selected")
        for table in tables:
            cmd.extend(["-t", table])

    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            logger.error("pg_dump failed: %s", result.stderr)
            _remove_file(filepath)
            raise HTTPException(status_code=500, detail="pg_dump failed; see the server log for details")

        # The dump contains password hashes and provider credentials. Serve it once
        # and delete it instead of accumulating copies in the backups volume.
        return FileResponse(
            filepath,
            media_type="application/sql",
            filename=filename,
            headers={"Content-Disposition": f"attachment; filename={filename}"},
            background=BackgroundTask(_remove_file, filepath),
        )

    except subprocess.TimeoutExpired:
        _remove_file(filepath)
        raise HTTPException(status_code=500, detail="Backup timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="pg_dump not found")


@router.post("/restore")
async def restore_backup(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Restore database from a SQL dump file."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    # Authenticating this request opened a transaction that holds a lock on
    # `users`. psql's DROP/ALTER statements would wait on it forever (until the
    # timeout), so release this request's connection before restoring.
    if isinstance(db, Session):
        db.close()
    params = get_db_params()
    if not params:
        raise HTTPException(status_code=500, detail="Database URL not configured")

    if not (file.filename or "").lower().endswith(".sql"):
        raise HTTPException(status_code=400, detail="Only .sql files are accepted")

    restore_path: Path | None = None
    sanitized_path: Path | None = None
    try:
        restore_dir = Path(BACKUP_DIR)
        restore_dir.mkdir(parents=True, exist_ok=True)
        restore_fd, raw_restore_path = tempfile.mkstemp(
            prefix="restore_",
            suffix=".sql",
            dir=restore_dir,
        )
        restore_path = Path(raw_restore_path)
        uploaded_bytes = 0
        with os.fdopen(restore_fd, "wb") as destination:
            while chunk := await file.read(RESTORE_CHUNK_SIZE):
                destination.write(chunk)
                uploaded_bytes += len(chunk)
        if uploaded_bytes == 0:
            raise HTTPException(status_code=400, detail="Backup file is empty")

        sanitized_fd, raw_sanitized_path = tempfile.mkstemp(
            prefix="restore_safe_",
            suffix=".sql",
            dir=restore_dir,
        )
        os.close(sanitized_fd)
        sanitized_path = Path(raw_sanitized_path)
        try:
            _sanitize_restore_file(restore_path, sanitized_path)
        except UnsafeRestoreError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

        env = os.environ.copy()
        env["PGPASSWORD"] = params["password"]
        result = subprocess.run(
            [
                "psql",
                "-h", params["host"],
                "-p", params["port"],
                "-U", params["user"],
                "-d", params["dbname"],
                "--no-psqlrc",
                "-v", "ON_ERROR_STOP=1",
                "--single-transaction",
                "-f", str(sanitized_path),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            logger.error("Restore failed: %s", result.stderr)
            if "backslash commands are restricted" in (result.stderr or ""):
                raise HTTPException(
                    status_code=400,
                    detail="Restore rejected: the file contains psql meta-commands",
                )
            raise HTTPException(status_code=500, detail="Restore failed; see the server log for details")

        return {"message": "Database restored successfully"}

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Restore timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="psql not found")
    finally:
        for path in (restore_path, sanitized_path):
            if path is None:
                continue
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove temporary restore file %s", path, exc_info=True)


@router.post("/clear-image-cache")
def clear_image_cache(current_user: User = Depends(get_current_user)):
    """Clear the image cache directory (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    import shutil
    images_dir = "/app/images"
    if os.path.exists(images_dir):
        shutil.rmtree(images_dir)
        os.makedirs(images_dir, exist_ok=True)
    return {"message": "Image cache cleared"}
