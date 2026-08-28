# Deploying Fider on a VPS (without Docker)

This guide explains how to run Fider on a single VPS using a plain
PostgreSQL database, the compiled Fider binary and a reverse proxy (nginx).
It is an alternative to the Docker-based setup and gives you full control
over every component.

## Architecture

```
                        +--------------------+
   :443 / :80           |   nginx (reverse   |
   client  <----------> |   proxy + TLS)     |
                        +--------------------+
                                   |
                                   | 127.0.0.1:3000
                        +--------------------+
                        |   fider (Go binary)|
                        |  ./fider           |
                        +--------------------+
                                   |
                                   | 127.0.0.1:5432
                        +--------------------+
                        |   PostgreSQL 16+   |
                        +--------------------+
```

## Prerequisites

One VPS running Ubuntu 22.04 or 24.04 (other distros work too, adjust the
package commands). Minimum 1 vCPU / 1 GB RAM.

| Software  | Version          | Notes                              |
|-----------|------------------|------------------------------------|
| Go        | 1.27+            | build-time only                    |
| Node.js   | 22               | build-time only                    |
| nginx     | any recent       | reverse proxy + TLS                |
| PostgreSQL| 16 or 17         | runtime dependency                 |

You can build on the server itself (needs Go + Node during the build step).
See [Build Fider](#2-build-fider).

## 1. Install PostgreSQL

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib nginx ufw certbot python3-certbot-nginx
sudo systemctl enable --now postgresql
```

Create the database and user:

```bash
sudo -u postgres psql
```

```sql
CREATE USER fider WITH PASSWORD 'change_me_to_a_long_random_password';
CREATE DATABASE fider OWNER fider;
\q
```

Test the connection (the binary connects on `127.0.0.1:5432` by default):

```bash
psql "postgres://fider:change_me_to_a_long_random_password@127.0.0.1:5432/fider?sslmode=disable" -c "SELECT 1"
```

## 2. Build Fider

Go to the repository root and run:

```bash
npm i
make build
```

This produces:

* `fider` – the server binary
* `dist/`      – frontend (JS/CSS) bundles
* `ssr.js`     – server-side rendering script
* `locale/`    – compiled translations
* `migrations/`– database migrations
* `views/`     – email / page templates
* `static/`    – static assets
* `favicon.png`, `robots.txt`

`make build` runs `build-server`, `build-ssr` and `build-ui`. If `make`
complains about missing `godotenv` or NPM dependencies, run
`npm install` (and optionally `go install github.com/joho/godotenv/cmd/godotenv@latest`)
first.

## 3. Install the runtime files

Create a dedicated user and directory:

```bash
sudo useradd --system --home /opt/fider --shell /usr/sbin/nologin fider
sudo mkdir -p /opt/fider
sudo chown -R fider:fider /opt/fider
```

Copy every file the binary needs at runtime (paths are relative to the
working directory of the process):

```bash
sudo cp fider /opt/fider/
sudo cp -r dist ssr.js locale migrations views static /opt/fider/
sudo cp favicon.png robots.txt /opt/fider/
```

Optionally add legal documents (makes `/privacy` and `/terms` available):

```bash
sudo mkdir -p /opt/fider/etc
sudo cp etc/privacy.md etc/terms.md /opt/fider/etc/
```

The uploads and user-uploaded images are stored in the database
(`BLOB_STORAGE=sql`, the default), so no filesystem storage volume is
needed.

## 4. Configure environment variables

Create `/etc/fider/fider.env` with permissions readable only by the fider
user:

```bash
sudo mkdir -p /etc/fider
sudo chown root:fider /etc/fider && sudo chmod 750 /etc/fider
sudo install -o root -g fider -m 640 /dev/null /etc/fider/fider.env
```

```ini
# /etc/fider/fider.env
GO_ENV=production

# Public URL of your instance (required, no trailing slash)
BASE_URL=https://feedback.example.com

# PostgreSQL connection string
DATABASE_URL=postgres://fider:change_me_to_a_long_random_password@127.0.0.1:5432/fider?sslmode=disable

# Used to sign cookies and tokens. Generate with:
#   openssl rand -base64 48
JWT_SECRET=generate_a_long_random_secret_here

# 'From' address used for outgoing emails
EMAIL_NOREPLY=noreply@example.com

# Email via SMTP. Fider also supports Mailgun (EMAIL_MAILGUN_*) and
# AWS SES (EMAIL_AWSSES_*) — see app/pkg/env/env.go.
EMAIL_SMTP_HOST=smtp.example.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=
EMAIL_SMTP_PASSWORD=

# Logging
LOG_LEVEL=INFO
LOG_SQL=false
```

The **required** variables are `DATABASE_URL`, `JWT_SECRET`, `EMAIL_NOREPLY`
and, in single-tenant mode (`HOST_MODE=single`, the default), `BASE_URL`.
SMTP is the fallback email type, so `EMAIL_SMTP_HOST` and `EMAIL_SMTP_PORT`
are required when no Mailgun/SES credentials are present.

### Optional: Firebase App Check and Auth

Firebase provisioning (see `docs/plans/firebase-app-check-anonymous-provisioning.md`)
is opt-in. When enabled, the server needs:

* `FIREBASE_PROJECT_ID` — the Firebase project used to verify tokens.
* `FIREBASE_PROJECT_NUMBER` — the numeric project number from Firebase Console
  → Project Settings → General; App Check uses this instead of the project ID.
* `FIREBASE_APP_IDS` — comma-separated Firebase App IDs (e.g.
  `1:1234567890:android:abc123`), not package/bundle IDs.
* `APP_CHECK_MODE` — `off` (default), `monitor`, or `enforce`.

Token verification uses Google's public signing keys. No Firebase Admin service
account or `GOOGLE_APPLICATION_CREDENTIALS` setting is required.

```ini
# /etc/fider/fider.env
FIREBASE_PROJECT_ID=example-project
FIREBASE_PROJECT_NUMBER=1234567890
FIREBASE_APP_IDS=1:1234567890:android:abc123,1:1234567890:ios:def456
APP_CHECK_MODE=monitor
```

Notes:

* Any mode other than `off` requires outbound HTTPS access to Google (Firebase)
  — the server fetches Google's signing keys during startup and when verifying
  tokens. `fider` fails fast at boot (exits with a clear error) if the App Check
  signing-key fetch fails, so verify the configuration before restarting a
  running site.
* Start in `monitor` with an attested client, watch
  `fider_app_check_verifications_total`, then switch to `enforce`. Firebase
  provisioning itself always requires a valid App Check token, even while the
  server only monitors legacy traffic.

Full reference of every variable: `app/pkg/env/env.go`.

## 5. Run Fider as a systemd service

Create `/etc/systemd/system/fider.service`:

```ini
[Unit]
Description=Fider
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=fider
Group=fider
WorkingDirectory=/opt/fider
EnvironmentFile=/etc/fider/fider.env
ExecStartPre=/opt/fider/fider migrate
ExecStart=/opt/fider/fider
Restart=always
RestartSec=5
LimitNOFILE=1024
# Lock down the process
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/fider

[Install]
WantedBy=multi-user.target
```

`ExecStartPre` runs database migrations before the server starts — identical
to what the Docker image does with `CMD ./fider migrate && ./fider`.

Start and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fider
sudo systemctl status fider

# health check (also used by the Docker HEALTHCHECK)
curl http://127.0.0.1:3000/_health
```

## 6. Reverse proxy with nginx

Create `/etc/nginx/sites-available/fider`:

```nginx
server {
    listen 80;
    server_name feedback.example.com;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/fider /etc/nginx/sites-enabled/fider
sudo nginx -t && sudo systemctl reload nginx
```

Obtain a TLS certificate (uses the config above):

```bash
sudo certbot --nginx -d feedback.example.com
```

certbot rewrites the config to listen on 443 with a redirect from :80.

## 7. Firewall

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Do not expose port 3000 – only nginx should be reachable.

## First run

Open `https://feedback.example.com` in a browser. The first visit asks you
to create the site (tenant) and the administrator account — the web app
itself performs the initial provisioning. No extra step is required.

## Upgrading to a new version

```bash
cd /path/to/repo
git pull
npm install
make build

sudo systemctl stop fider
sudo cp fider /opt/fider/
sudo systemctl start fider       # runs migrations on the new binary
```

Check the changelog/release notes for the target version before upgrading,
especially for migration notes.

## Backups

Back up the PostgreSQL database. The default `BLOB_STORAGE=sql` keeps all
uploaded images inside the database, so a single `pg_dump` covers everything:

```bash
# nightly cron: sudo crontab -e
0 2 * * * pg_dump "postgres://fider:password@127.0.0.1:5432/fider" | gzip > /backup/fider_$(date +\%F).sql.gz
```

Test the restore path:

```bash
gunzip < fider_2026-08-17.sql.gz | psql "postgres://fider:password@127.0.0.1:5432/fider"
```

If you switch `BLOB_STORAGE` to `fs` or `s3`, remember to back those up too.

## Hardening notes

* Run only `fider`, `postgres`, `nginx` — no Docker daemon required.
* Keep `JWT_SECRET` and the DB password long and random; rotate on compromise.
* `ProtectSystem=strict` + `ReadWritePaths=/opt/fider` in the unit file keep
  failures from touching the rest of the filesystem.
* Set `BLOB_STORAGE_FS_PATH` (and `BLOB_STORAGE=fs`) if you prefer uploaded
  files on disk over the database.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `could not find environment variable named 'JWT_SECRET'` | Missing required var in `/etc/fider/fider.env`; `EnvironmentFile=/etc/fider/fider.env` must point at the right file. |
| `failed to parse environment variables` at startup | A variable has an invalid value (e.g. bad URL in `BASE_URL`). Check `journalctl -u fider`. |
| 502 Bad Gateway | `fider` is not running or failed after `migrate`. Check `systemctl status fider` and `journalctl -u fider`. |
| Migration fails on upgrade | Postgres version too old; run `sudo systemctl status postgresql`. Logs in `journalctl -u fider`. |
| Login emails never arrive | SMTP settings wrong. Test with `curl --ssl smtp://...`? Set `EMAIL_SMTP_PORT=587` for STARTTLS or `465` with `EMAIL_SMTP_ENABLE_IMPLICIT_TLS=true`. |
