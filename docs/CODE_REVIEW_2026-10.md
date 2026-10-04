# Engineering & Security Review — October 2026

Scope: full repository at `d18db13` (v1.51.0): FastAPI backend, React/Vite
frontend, Docker/nginx deployment, CI. Review was done by reading the code,
running both test suites, running `pip-audit` / `npm audit`, and
reproducing the behaviour behind the findings marked **verified**.

Severity: **Critical** = remote compromise is realistic on a default install;
**High** = security or availability impact likely in common deployments;
**Medium** = real issue but needs a specific setup or has limited blast
radius; **Low** = hardening / hygiene.

---

## Summary

The codebase is far more defensive than its "vibecoded" disclaimer suggests:
ownership filters are applied consistently, upload paths are bounded
(byte limits, pixel limits, decompression-bomb guards), the JWT secret
handling has been hardened, the custom-image proxy has an SSRF guard, the
public-profile API is carefully scoped, and the frontend has no raw-HTML
sinks and ships a strict CSP.

The main risks are at the **edges**: the default deployment posture
(unauthenticated admin, backend port published, permissive CORS), the
database restore endpoint, rate limiting that does not see real client IPs,
stale/vulnerable dependencies, and backend tests that never run in CI.

| # | Severity | Finding |
|---|----------|---------|
| 1 | Critical | Default single-user mode + multipart restore endpoint → drive-by RCE |
| 2 | High | CORS `*` with `allow_credentials=True` reflects any origin |
| 3 | High | Rate limiting keys on the nginx container IP (shared by all users) — **verified** |
| 4 | High | Known-vulnerable / unmaintained dependencies — **verified** |
| 5 | High | Backend port 8000 published directly, bypassing nginx |
| 6 | Medium | Any trainer can set image URLs on shared catalogue cards; proxy accepts SVG; DNS-rebinding gap |
| 7 | Medium | Any trainer can read any other trainer's collection incl. purchase prices |
| 8 | Medium | Session / password-lifecycle gaps |
| 9 | Medium | Generic settings endpoints accept arbitrary keys; secrets stored and exported in plaintext |
| 10 | Medium | Backups accumulate forever on disk and contain secrets |
| 11 | Low | Internal error text returned to clients |
| 12 | Low | Container hardening |

Efficiency, architecture, test/CI gaps, and missing features follow in later
sections.

---

## 1. Security findings

### 1.1 Critical — Default unauthenticated admin + restore endpoint = drive-by RCE

**Where:** `backend/api/auth.py` (`multi_user_enabled`, `get_current_user`),
`backend/database.py` (`DEFAULT_SETTINGS["multi_user_mode"] = "false"`),
`backend/api/backup.py` (`restore_backup`).

- A fresh install starts in **single-user mode**: any request *without* a
  token is treated as the first active admin.
- `POST /api/backup/restore` takes a `multipart/form-data` upload and runs it
  with `psql -f`. psql runs **meta-commands** in script files, so a file
  containing `\! <shell command>` runs that command in the backend container.
  The `pokemon` role is also a Postgres superuser in the stock
  `postgres` image, so `COPY ... FROM PROGRAM` gives code execution in the DB
  container too. `--single-transaction` and `ON_ERROR_STOP` don't stop either.
- `multipart/form-data` is a CORS-safelisted content type. A malicious web
  page can send `fetch(url, {method: "POST", mode: "no-cors", body: formData})`
  to `http://<lan-ip>:3000/api/backup/restore` (or `:8000`) **with no
  preflight**. The attacker can't read the response, but doesn't need to.
  Browser Local/Private-Network-Access protections reduce this risk but
  aren't universal. DNS rebinding works around them as well.

The same no-preflight POST pattern also reaches other state-changing
multipart endpoints (CSV imports, scan uploads).

**Recommendations (in priority order):**
1. Never pass user-uploaded SQL through `psql`. Switch backups to
   `pg_dump -Fc` and restore with `pg_restore` (no shell escapes), or at
   minimum reject any line matching `^\s*\\` and `FROM PROGRAM` before
   running. Better still, run restore as a non-superuser role.
2. Add CSRF protection that forces a preflight: require a custom header
   (e.g. `X-Requested-With: pokecollector`) on every non-GET `/api/*` request
   and reject requests without it. axios can add it globally in
   `frontend/src/api/client.js`.
3. Even in single-user mode, require a confirmation secret (or a local-only
   bind) for destructive admin operations (restore, user mode toggle, sync
   controls).
4. Make the docs and first-run UI loud about single-user mode on anything
   other than a trusted LAN.

### 1.2 High — CORS wildcard with credentials reflects arbitrary origins

**Where:** `backend/main.py` — `allow_origins=["*"]` (when `CORS_ORIGINS` is
unset, which is the default) together with `allow_credentials=True`.

Starlette (0.36.3, `middleware/cors.py`) handles this combination by
**echoing the request's `Origin`** with `Access-Control-Allow-Credentials:
true` on preflights, and on simple requests whenever a `Cookie` header is
present. Bearer tokens are unaffected, but the documented reverse-proxy-auth
deployments (Authentik/Authelia/oauth2-proxy, `docs/REVERSE_PROXY_AUTH.md`)
authenticate with **cookies**. Combined with single-user mode behind the
proxy, any page that can get the proxy cookie sent can read every API
response cross-origin. That includes `/api/backup/download`, which contains
password hashes and API keys. Examples are a same-site subdomain or a proxy
cookie set to `SameSite=None`.

**Recommendation:** default to same-origin only (no CORS middleware, since the
SPA is served behind the same nginx). Allow explicit origins only through
`CORS_ORIGINS`, and refuse to start with `*` + credentials.

### 1.3 High — Rate limiting sees one IP for every user (verified)

**Where:** `backend/main.py` (`Limiter(key_func=get_remote_address,
default_limits=["60/minute"])`, custom `login_rate_limit` middleware),
`backend/Dockerfile` (`uvicorn` without `--proxy-headers
--forwarded-allow-ips`).

- uvicorn only trusts `X-Forwarded-For` from `127.0.0.1` by default. nginx
  runs in a different container, so `request.client.host` is the **nginx
  container IP for every user**.
- **Verified** with `TestClient`: 65 calls to `/api/health` → 60× 200, 5× 429.
  The default limit covers *every* route, including `/api/images/*`.
- Effects:
  - **Availability:** all users of an instance share **60 requests/minute**.
    A cold card gallery or dashboard can use that up alone, and then
    unrelated users get 429s and placeholder card art.
  - **Login DoS:** the 5 logins/minute limit is global, so one attacker
    (or a typo-prone family) locks *everyone* out.
  - **Brute-force protection is weaker than it looks:** the limiter is
    in-memory and per-process. With `--workers N` the budget multiplies, and
    a restart resets it.
  - Port 8000 is also published directly (see 1.5). Clients that hit it get
    their own bucket, so the protection is inconsistent.

**Recommendations:** run uvicorn with `--proxy-headers
--forwarded-allow-ips=<nginx subnet>` (or read `X-Real-IP` in a custom key
function that only trusts the proxy). Exempt `/api/images/*` and
`/api/health`. Raise the default to something realistic for a SPA
(e.g. 600/min). Key login throttling on **username + IP** and back it with
the DB or Redis if multiple workers are ever used.

### 1.4 High — Vulnerable / unmaintained dependencies (verified)

`pip-audit -r backend/requirements.txt` and `npm audit --omit=dev`:

| Package | Version | Issue |
|---|---|---|
| `starlette` (via `fastapi==0.109.2`) | 0.36.3 | 7 advisories, fixes in 0.40.0 → 1.3.1 (includes the multipart-form DoS fixed in 0.40.0) |
| `python-jose` | unpinned (3.5.0) | Unmaintained. Pulls in `ecdsa` 0.19.2 (advisory with no fix). History of algorithm-confusion and JWE-bomb CVEs. |
| `bcrypt` | **unpinned** (5.0.0 resolved) | 5.x **raises `ValueError` for passwords > 72 bytes** (verified). `hash_password` / `verify_password` don't truncate, so a long password causes a 500 on create, login, or change. |
| `axios` | ^1.18.0 → resolves ≤1.19.0 | 1 high, 11 advisories (prototype-pollution gadgets, header injection). Fix with `npm audit fix`. |
| `httpx` 0.26, `uvicorn` 0.27, `pandas` 2.2.0, `reportlab` 4.1.0 | pinned old | Not flagged by the audit, but well behind upstream. |

**Recommendations:** bump FastAPI/Starlette to current. Replace
`python-jose` with `PyJWT` (only HS256 is used, so it is a drop-in swap).
Pin `bcrypt` and either pre-hash (`sha256` → base64 → bcrypt) or enforce a
≤72-byte limit with a 422. Run `npm audit fix`. Add Dependabot/Renovate for
`pip`, `npm`, Docker base images, and GitHub Actions.

### 1.5 High — Backend port published directly

**Where:** `docker-compose.yml` → `backend.ports: "${BACKEND_PORT:-8000}:8000"`
on all interfaces.

Requests to `:8000` skip everything nginx provides: the CSP and security
headers, the `client_max_body_size` limits (old Starlette spools a whole
multipart body to disk before handlers enforce their limits), and the
`X-Real-IP` header. It also doubles the attack surface for 1.1/1.2.

**Recommendation:** remove the `ports` mapping from `backend` (nginx reaches
it on the compose network), or bind to `127.0.0.1:8000:8000` for local
debugging. Apply the same to the frontend if TLS is terminated by another
proxy on the host.

### 1.6 Medium — Shared catalogue image URLs, SVG, and DNS rebinding

**Where:** `backend/api/cards.py::update_card_custom_image`,
`backend/api/images.py::_get_or_fetch_custom_image`,
`backend/services/image_url_security.py`.

- `PUT /api/cards/{id}/custom-image` lets **any trainer** set
  `custom_image_url` on a *global* TCGdex card row that has no artwork. The
  image is then shown to **every user** of the instance (cross-tenant
  integrity; inappropriate-content vector).
- For non-custom cards the proxy uses `allowed_content_types=None`, which
  allows any `image/*` — **including `image/svg+xml`** — and serves it
  same-origin from `/api/images/card/...`. The nginx CSP blocks inline
  script, but direct requests to port 8000 (1.5) carry no CSP.
- `validate_public_https_image_url` resolves DNS and then lets httpx resolve
  again. A rebinding DNS server can pass validation and then connect to an
  internal address (TOCTOU). This is mitigated by HTTPS on port 443 only and
  by the response being an image, but it isn't closed.

**Recommendations:** store per-user overrides (`user_id`, `card_id`, `url`)
instead of mutating the shared `cards` row, or restrict this to admins.
Always use the raster allowlist (`_ALLOWED_CUSTOM_IMAGE_TYPES`). Add
`Content-Security-Policy: sandbox; default-src 'none'` and `nosniff` to every
`/api/images/*` response. Pin the connection to the validated IP (custom
httpx transport) or route through an egress proxy.

### 1.7 Medium — Cross-trainer collection access exposes purchase prices

**Where:** `backend/api/collection.py::get_user_collection`
(`GET /api/collection/user/{user_id}`).

Any authenticated trainer can list any active trainer's full non-custom
collection, including `purchase_price`. The public-profile system has
careful opt-ins (profile, per-binder sharing, `show_values`), but this
endpoint ignores them all. In a household or club instance this leaks
financial data.

**Recommendation:** gate it behind a per-user "visible to other trainers"
setting, strip `purchase_price` (and notes, photos) unless the owner opts in,
and log access.

### 1.8 Medium — Session and password lifecycle gaps

**Where:** `backend/services/auth.py`, `backend/api/auth.py`.

- **No revocation.** JWTs last 7 days and carry no `iat`/`jti`/token version.
  Changing or resetting a password, or demoting a user, doesn't invalidate
  existing tokens. Deactivation does, because `is_active` is re-checked. Add
  a `token_version` column checked in `get_current_user`.
- **`must_change_password` is only enforced in the UI.** The API serves every
  endpoint to a user who still has to change their password.
- **No password policy.** Empty or 1-character passwords are accepted by
  `create_user`, `update_user`, `change_password`, and
  `force_change_password`. Combined with the bcrypt 5 issue (1.4), there is
  no lower *or* upper bound.
- **`role` isn't validated.** Any string is stored (`CreateUserRequest.role:
  str`). Use `Literal["admin", "trainer"]`.
- **Bootstrap admin password is logged in plaintext** by default
  (`ADMIN_BOOTSTRAP_LOG=true`) and isn't marked `must_change_password`.
  Container logs are often shipped to third parties.
- **Username enumeration by timing.** A missing user skips bcrypt. Run a
  dummy `checkpw` on that path.

### 1.9 Medium — Settings storage

**Where:** `backend/api/settings.py` (`PUT /api/settings/`,
`POST /api/settings/{key}`).

- Any authenticated user can write **arbitrary keys with unbounded values**
  into `user_settings`. Only managed scanner keys and admin-only keys are
  refused. That allows storage abuse, and future code that reads a key
  without validating it inherits attacker data. Whitelist with
  `PER_USER_KEYS` and cap value length.
- Gemini/OpenAI API keys and Telegram bot tokens are stored **in plaintext**,
  and the Telegram token (including the `TELEGRAM_BOT_TOKEN` env fallback for
  admins) is **returned to the browser** by `GET /api/settings/`. Return a
  `configured: true` flag instead, as the scanner keys already do. Consider
  encrypting secrets at rest with a key derived from the server secret.

### 1.10 Medium — Backup files accumulate and contain secrets

**Where:** `backend/api/backup.py::download_backup`.

Each download writes `/app/backups/pokemon_tcg_backup_<ts>.sql` (mounted to
`./backups` on the host) and **never deletes it**. Every file contains
password hashes and plaintext API keys and bot tokens. Disk usage grows
without bound, and the host directory becomes a high-value target.

**Recommendation:** stream `pg_dump` to the response (or use a temp file plus
a `BackgroundTask` to delete it), and document `chmod 700 ./backups`.
Pre-upgrade backups already have a retention setting
(`PRE_UPGRADE_BACKUP_KEEP`). Manual downloads should not persist.

### 1.11 Low — Internal error text returned to clients

`pg_dump failed: {stderr}`, `Restore failed: {stderr}` (`api/backup.py`), and
`HTTPException(500, detail=str(e))` (`api/cards.py::get_card` and others)
leak hostnames, SQL, and stack details. Log server-side and return a generic
message plus a correlation ID.

### 1.12 Low — Container and deployment hardening

- Both images run as **root**. Add a non-root `USER` to the backend image.
  nginx can use `nginxinc/nginx-unprivileged`.
- `POSTGRES_PASSWORD` defaults to `changeme`. Refuse to start with it, or
  generate one on first run as is done for the JWT secret.
- nginx: the static-asset `location` uses `add_header`, which **drops all
  server-level security headers** (CSP, `X-Frame-Options`, …) for JS/CSS
  because of nginx's add_header inheritance rules. Repeat them or use an
  `include` snippet. No HSTS guidance for TLS deployments.
- The backend image keeps `gcc`, `wget`, and `gnupg` after build. Use a
  multi-stage build.

---

## 2. Efficiency & scalability

| Area | Issue | Suggestion |
|---|---|---|
| Image proxy (`api/images.py`) | Sync `def` endpoints make blocking upstream `httpx` calls (up to 15 s) inside Starlette's ~40-thread pool. A cold gallery can use up the pool and stall *all* sync endpoints. `_get_or_fetch` (TCGdex path) follows redirects and has **no size cap**. | Make these `async` with a shared `httpx.AsyncClient`, cap the response size, and limit concurrency per upstream. |
| Image cache storage | Image bytes are stored as rows in Postgres (`image_cache`) with **no eviction or size limit**. This bloats the DB, WAL, and every full backup that includes images. | Store on disk or object storage with an LRU, or at least add a TTL / size budget and a scheduled vacuum. |
| Search (`services/text_search.py`) | `unaccent(lower(col)) LIKE '%term%'` can't use a btree index → sequential scan over `cards` on every keystroke. Without `unaccent` (hosted DBs) the fallback nests **56 `REPLACE()` calls per column**, which is slow on Postgres and *crashes* SQLite (see §4). The availability probe calls `db.rollback()` mid-request, which discards any pending writes in the caller's session. | Add an immutable `unaccent` wrapper plus a `pg_trgm` GIN index, or a precomputed `search_text` column filled at sync time. Probe availability once at startup on its own connection. |
| Async handlers with sync DB | `api/recognize.py::recognize_card` and the helpers it calls are `async def` but run synchronous SQLAlchemy queries, which **blocks the event loop** for every request on that worker. | Use `def` for DB-heavy handlers, wrap DB work in `run_in_threadpool`, or move to async SQLAlchemy. |
| Unpaginated lists | `GET /api/collection/` and `/api/collection/user/{id}` return every row with joined card/set data. Analytics and dashboards also aggregate in Python. | Add cursor pagination. Push aggregates (`SUM`, `GROUP BY`) into SQL. |
| TCGdex client (`services/pokemon_api.py`) | A new `httpx.Client` per call, so no connection or TLS reuse during syncs of thousands of cards. | Use a module-level client with keep-alive and bounded concurrency. |
| Exchange rates (`api/settings.py::get_exchange_rate`) | Calls `frankfurter.dev` on every request with no caching. | Cache per currency pair for about an hour. |
| Backup/restore | Synchronous, with a hard 120 s timeout. Large DBs (especially with `images`) fail, and a worker is held the whole time. | Run as a background job with progress, stream the output, and make the timeout configurable. |

---

## 3. Architecture pitfalls

1. **Single-process assumptions.** APScheduler runs in-process
   (`services/scheduler.py`), login attempts live in `app.state`, and several
   module-level caches exist. Running `uvicorn --workers N` or more than one
   replica would **duplicate every sync and price job** and break throttling.
   Either document "exactly one worker" loudly, or add a DB advisory lock
   around scheduled jobs and move shared state to Postgres or Redis.
2. **Hand-rolled migrations.** `database.py::_run_migrations` runs about
   600 lines of idempotent `ALTER`/`UPDATE` statements on every startup.
   `alembic` is in `requirements.txt` but unused. There is no version table,
   no down-migrations, and no way to tell which migrations ran. Restoring an
   older dump isn't re-migrated until the next restart. Startup time grows
   with history. The pre-upgrade backup is a good safety net, but adopt
   Alembic with a baseline revision.
3. **Very large modules.** `api/binders.py` (2.6k lines), `api/recognize.py`
   (1.7k), `api/trades.py`, and `api/cards.py` mix HTTP, business logic, and
   persistence. Moving logic into `services/` (as already done for decks)
   would make it testable without `TestClient`.
4. **User deletion is hand-maintained.** `api/auth.py::delete_user` deletes
   from about 15 tables one at a time. Newer tables (`scan_jobs`,
   `printing_detail_tags`, `scan_queue_user_state`) rely on `ON DELETE
   CASCADE` instead. That works, but it's inconsistent, and on-disk scan
   uploads tied to cascaded jobs may be left orphaned. Prefer DB cascades
   everywhere, plus a filesystem cleanup hook.
5. **Selective backups are incomplete** (already documented in the README).
   Trades, collection photos, and newer tables aren't in any group. This is
   a data-loss trap for anyone who uses "collection" as their backup.

---

## 4. Testing & CI gaps

- **Backend tests never run in CI.** `.github/workflows/` only runs the
  frontend card-system suite, version checks, and the release. The 78
  backend test files are run only by hand.
- **Local backend run: 901 passed, 64 failed, 19 skipped.** All 64 failures
  have one root cause: `sqlite3.OperationalError: parser stack overflow`
  (SQLite 3.45.1) from the 56-deep nested `REPLACE()` accent fallback in
  `services/text_search.py`. They affect accent search, rule-text search,
  card search query params, collection rule-text search, and recognizer
  candidate search. Results therefore depend on the SQLite build; the
  failures would have been caught in CI. Replacing the nesting with a
  registered SQLite function (`create_function("unaccent", ...)`) in tests,
  or a precomputed column, fixes both the tests and the performance issue.
- No Postgres-backed CI job, although `test_*_postgres.py` files exist.
- No dependency or secret scanning, SAST, or container image scanning.
- Frontend: **317/317 vitest tests pass**. There are no end-to-end tests for
  auth, permissions, or multi-user isolation.

**Recommendation:** add a `backend.yml` workflow with a Postgres 18 service
running `pytest`, plus `pip-audit`, `npm audit --omit=dev`, and Trivy on the
built images.

---

## 5. Feature gaps

- **Authentication:** no 2FA, no OIDC/SSO (only trusted reverse-proxy
  setups, which the backend doesn't verify through headers), no self-service
  password reset, no session list or "log out everywhere", and no audit log
  of admin actions (user changes, restores, mode toggles).
- **Authorization:** two hard-coded roles (`admin`/`trainer`), with checks
  repeated in each route. A `require_admin` dependency would remove the ~19
  copy-pasted `role != "admin"` checks and the risk of forgetting one.
- **Privacy controls:** no per-user opt-out from leaderboard and
  cross-trainer viewing (see 1.7), and no "export / delete my data"
  self-service.
- **Operations:** no `/metrics` or readiness probe that checks the DB (the
  current `/api/health` is static), no structured or JSON logs, and no
  scheduled automatic backups (only pre-upgrade backups).
- **Data:** no off-site backup target (S3/WebDAV), and restore doesn't
  validate version compatibility before dropping tables.

---

## 6. Suggested remediation order

1. Stop using `psql` for restore (or filter meta-commands), add a CSRF
   header check, and drop the CORS wildcard (1.1, 1.2).
2. Remove the published backend port and add uvicorn proxy headers plus
   sensible rate limits (1.3, 1.5).
3. Upgrade FastAPI/Starlette, replace `python-jose`, pin `bcrypt` and handle
   the 72-byte limit, and run `npm audit fix` (1.4).
4. Add the backend CI workflow and fix the SQLite accent fallback (§4).
5. Restrict shared-card image overrides, scope cross-trainer collection
   reads, and add token versioning plus a password policy (1.6–1.8).
6. Clean up backups and settings handling, then the efficiency items (§2).
