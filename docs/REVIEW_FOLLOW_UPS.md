# Review follow-ups

Open items from the [October 2026 review](CODE_REVIEW_2026-10.md) that need a
design decision or are larger than a hardening pass. Issues are disabled on
this repository, so they are tracked here. Remove an entry when it is fixed.

## Security

### S1. Run database restore as a non-superuser role
*Finding 1.1, residual.* Restores run inside psql `\restrict` mode, so
meta-commands such as `\!` are refused, and a literal `COPY ... PROGRAM` is
rejected. The SQL still runs as `pokemon`, which is a **superuser** in the stock
`postgres` image. An admin-supplied dump can therefore still run code in the DB
container through SQL alone, for example
`DO $$ BEGIN EXECUTE 'COPY t FROM PRO' || 'GRAM ''id'''; END $$;`, or read
server files with `pg_read_file`.

- Create a dedicated non-superuser role that owns the schema, used by the app
  and by restore. Keep the superuser only for bootstrap and `CREATE EXTENSION`.
- Alternatively, restore into a scratch database as a restricted role and swap
  it in.
- Existing installs need a migration (`REASSIGN OWNED`) documented in
  `scripts/`, like the PG 15→18 upgrade.

Files: `backend/api/backup.py`, `docker-compose.yml`, `backend/database.py`,
`docs/DEPLOYMENT.md`.

### S2. Per-user image overrides for shared catalogue cards; DNS-rebinding-safe fetching
*Finding 1.6.*
- `PUT /api/cards/{id}/custom-image` lets **any trainer** set
  `custom_image_url` on a *global* TCGdex card row without artwork, and every
  user then sees it. Proxied images are already restricted to raster formats
  and sandboxed, so this is no longer an XSS vector, but it is a cross-tenant
  integrity problem. Store overrides per user (`user_id`, `card_id`, `url`), or
  make the endpoint admin-only in multi-user mode.
- `validate_public_https_image_url` resolves the host, then httpx resolves it
  again when connecting. A rebinding DNS server can pass the check and then
  connect to an internal address. Connect to the validated IP with a custom
  httpx transport (SNI/Host set to the original name), or use an egress proxy.

Files: `backend/api/cards.py`, `backend/api/images.py`,
`backend/services/image_url_security.py`, `backend/models.py`.

### S3. Encrypt provider secrets at rest; stop returning the Telegram token
*Finding 1.9.* Gemini/OpenAI keys and Telegram bot tokens are stored in
plaintext and are included in every full backup. `GET /api/settings/` returns
`telegram_bot_token` to the browser, including the env fallback for admins.

1. Make the Telegram token write-only, as scanner keys already are: return a
   `*_configured` flag and give `Settings.jsx` a "configured – replace / clear"
   state.
2. Encrypt secret settings (Fernet/AES-GCM) with a key derived from the server
   secret or a separate `SECRETS_KEY`. Include a migration for existing rows.

### S4. Require changing the auto-generated bootstrap admin password
*Finding 1.8.* Without `ADMIN_PASSWORD`, the generated password is logged in
plaintext by default (`ADMIN_BOOTSTRAP_LOG=true`), and the account is not
marked `must_change_password`. Simply setting the flag breaks the first run:
new installs are single-user, and the UI would immediately show the
forced-change screen.

Options:
- Report the flag from `/api/auth/me` only in multi-user mode.
- Or require the admin to set a password when enabling multi-user mode.

Also consider defaulting `ADMIN_BOOTSTRAP_LOG` to `false`.

Files: `backend/services/auth.py`, `backend/api/auth.py`, `frontend/src/App.jsx`,
`frontend/src/pages/Settings.jsx`.

### S5. Container hardening
*Finding 1.12.*
- **Non-root containers.** Add `USER` to `backend/Dockerfile` and switch the
  frontend to `nginx-unprivileged`. Existing root-owned bind mounts need a
  `chown` step in the release notes.
- **Default database password.** Refuse to start with the default
  `POSTGRES_PASSWORD=changeme`, or generate and persist one on first run.
- **Smaller backend image.** Use a multi-stage build so `gcc`, `wget` and
  `gnupg` don't ship.
- **HSTS.** Add guidance for TLS-terminating proxies.

### S6. Privacy controls for cross-trainer viewing
*Finding 1.7.* Purchase prices are now hidden from other trainers. Trainers
still can't opt out of the leaderboard or of other members viewing their
collection (`GET /api/collection/user/{id}`, `backend/api/social.py`). Add a
`collection_visibility: members | private` setting, honour a values preference
on the leaderboard, and offer "export / delete my data" self-service.

## Efficiency

### E1. Async image proxy and bounded image cache
`api/images.py` endpoints are sync and make blocking upstream calls inside the
~40-thread pool. A cold gallery can use up the pool. Image bytes live in
`image_cache` (Postgres bytea) with no eviction. Move the endpoints to `async`
with a shared `httpx.AsyncClient` and per-upstream concurrency limits. Store
images on disk or object storage with an LRU, or add a TTL / size budget.

### E2. Blocking work on the event loop and connection reuse
`api/recognize.py::recognize_card` and its helpers are `async def` but run
synchronous SQLAlchemy queries, which blocks the event loop. Use `def`
handlers or `run_in_threadpool` for the DB work.
`services/pokemon_api.py` creates a new `httpx.Client` per call, so syncs get
no keep-alive. Use a module-level client.

### E3. Indexed search and pagination
`unaccent(lower(col)) LIKE '%term%'` scans the whole table. Add an immutable
`unaccent` wrapper plus a `pg_trgm` GIN index, or a precomputed `search_text`
column filled at sync time. `GET /api/collection/` and
`/api/collection/user/{id}` are unpaginated. Add cursor pagination and push
analytics aggregates into SQL.

### E4. Backups as background jobs
Backup and restore run synchronously with a hard 120 s timeout, so large
databases (especially with images) fail. Run them as background jobs with
progress, stream the output, and make the timeout configurable. Selective
backup groups also miss trades, collection photos and newer tables.

## Architecture

### A1. Single-process assumptions
APScheduler runs in-process, and the rate limiter and login-failure tracking
are in memory. Running more than one uvicorn worker or replica duplicates
every scheduled sync and multiplies the rate-limit budgets. Take a Postgres
advisory lock around scheduled jobs, and allow a shared `limits` storage
(Redis) when scaling out.

### A2. Adopt Alembic
`database.py::_run_migrations` runs hundreds of lines of idempotent DDL on
every startup, with no version table or downgrade path. `alembic` is already
in `requirements.txt`. Add a baseline revision and move new schema changes
there.

### A3. Module size and user deletion
`api/binders.py` (2.6k lines), `api/recognize.py`, `api/trades.py` and
`api/cards.py` mix HTTP and domain logic; move logic into `services/`.
`api/auth.py::delete_user` deletes table by table, while newer tables rely
on `ON DELETE CASCADE`. Standardise on cascades and add cleanup of scan files
on disk.
