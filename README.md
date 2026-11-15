# job-platform-auth-svc

Auth service for **Vietnam Job Platform** (`pbl6`) — `dut-pbl6-2026`. `register` `login` `JWT` `refresh`, `Port 5001` `net10.0`.

## Overview

- `src/Auth.Api` — Web API `JWT Bearer` `Swagger` `health`
- `src/Auth.Core` — `User` `RefreshToken`
- `src/Auth.Infrastructure` — `AuthDbContext` `Npgsql` `Migrations` `JwtTokenService` `BCrypt 12`
- `tests` — `xunit` `PasswordHasher`
- `local-feed` — `JobPlatform.SharedKernel 0.1.0` via `nuget.config`

## Prerequisites

- `mise` https://mise.jdx.dev
- `docker` + `docker compose v2`
- `git` + `gh` `gh auth login`
- `dotnet 10.0.100` via `mise` — `mise trust && mise install`

See `AGENTS.md` for shell activation (`mise activate`) and agent `mise exec` notes.

## Clone

```bash
mkdir -p ~/projects/personal/job-platform && cd ~/projects/personal/job-platform
for r in infra shared auth-svc; do gh repo clone dut-pbl6-2026/job-platform-$r; done
cd job-platform-auth-svc
```

## Setup

```bash
mise trust && mise install
mise run sync-env
mise run verify  # 14
cat .env | grep DATABASE_URL_AUTH
```

Env single source: `../job-platform-infra/envs/.env.dev.example` → `.env` via `mise run sync-env`.

## Build

```bash
mise run build     # dotnet build --warnaserror
mise run test      # dotnet test
mise run format    # dotnet format --verify-no-changes
mise run ef-check
```

Update SharedKernel: `mise run pack-shared`.

## Run

```bash
mise run run              # dotnet run --project src/Auth.Api
curl http://localhost:5001/health   # {"status":"ok"}
curl -i -X POST http://localhost:5001/api/auth/register -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"SecureP@ss123","fullName":"Hoai"}' # 202 {"message":"Check your email to verify your account."}
curl -X POST http://localhost:5001/api/auth/verify-email -H 'Content-Type: application/json' -d '{"token":"<token from the emailed link>"}' # 200 (link valid 24h, single use)
curl -X POST http://localhost:5001/api/auth/login -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"SecureP@ss123"}' # 200 {accessToken,refreshToken,user} (401 until verified)
```

`UseExceptionHandler` + `ILogger`. The host does not migrate on startup: run `migrate` as a separate step first (see below).

Registration never reveals whether an email is taken: both cases return `202`. A new address gets a pending account and a verification link; an existing address gets a notice mail to its owner.

## Configuration

No connection string or secret is committed. Required environment variables:

- `DATABASE_URL_AUTH` (or `ConnectionStrings__AuthDb`): Npgsql connection string. Startup fails when missing. Copy it from `.env` (`mise run sync-env`).
- `Jwt__Secret`: at least 32 characters. Startup fails outside Development when missing. Development generates a per-process key when unset.
- `WEB_URL`: web app origin for verification and reset links. Startup fails outside Development when missing.
- `INTERNAL_SERVICE_TOKEN`: bearer token for `/api/internal/*` (not routed by the gateway). Unset means the endpoints return 401.
- `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`: outgoing mail for verification, password-reset and notice emails. Startup fails outside Development when any of the four is missing (the message lists the missing names, never the values). Optional: `SMTP_PORT` (default `587`), `SMTP_SSL` (default `true`, STARTTLS).
  - Production uses a Google account: `SMTP_HOST=smtp.gmail.com`, `SMTP_PASS` is a Google App Password (2-Step Verification on), and `SMTP_FROM` must equal `SMTP_USER` because Gmail rewrites the From address.
- `EMAIL_SENDER`: Development only. `log` writes each auth email, including its one-time link, to the console log and sends nothing (explicit opt-in). `smtp` forces SMTP. When unset, Development uses SMTP if `SMTP_HOST` is set and otherwise fails at startup, so emails are never silently dropped. `log` outside Development fails startup.
- Auth emails go through a durable outbox (`EmailOutboxMessages` table). The registration or reset request writes its row in the same transaction as the account change, then returns without waiting for SMTP. A background worker sends due rows every 5 s. Failed sends retry with exponential backoff (1, 2, 4, 8, 16, then 30 minutes) and are given up after 8 failed attempts, with an Error log that names the row id. Rows are claimed with a lease, so several replicas can run the worker. Delivery is at-least-once: a crash after SMTP accepts a message but before the row is marked sent can send one duplicate.
- `ForwardedHeaders__KnownNetworks`: the network the gateway runs in, comma-separated CIDRs or addresses (for example `10.0.0.0/8`). Only that peer may set `X-Forwarded-For`, so per-IP rate limits see the real client. **Required in Production.** Startup fails when it is empty or contains `0.0.0.0/0` or `::/0`. Use the gateway's exact subnet, not a wider one. Unset outside Production means forwarded headers are ignored.

## Schema migration (separate deploy step)

The web host never touches the schema on startup. Apply pending migrations with the one-off command, then start the service:

```bash
dotnet run --project src/Auth.Api -- migrate   # exit 0 when the database is up to date
```

In compose, the `auth-migrate` service runs this command and `auth` starts only after it completes successfully.

## Admin bootstrap (one-time)

The first Admin account is created by a one-time command, not by a manual DB insert. Public registration can never create an Admin.

```bash
# Local: export the two variables, then run the command (migrations run first, no HTTP server starts)
export ADMIN_BOOTSTRAP_EMAIL=admin@example.com
export ADMIN_BOOTSTRAP_PASSWORD='ChangeMe-Admin1'
dotnet run --project src/Auth.Api -- bootstrap-admin

# Docker: -e NAME without a value copies the variable from the host shell, so the secret stays off the command line
docker run --rm --env-file .env -e ADMIN_BOOTSTRAP_EMAIL -e ADMIN_BOOTSTRAP_PASSWORD auth bootstrap-admin
```

- `ADMIN_BOOTSTRAP_EMAIL` and `ADMIN_BOOTSTRAP_PASSWORD` are read from environment variables only. The password must meet the normal password policy (8+ characters, 1 uppercase, 1 digit).
- The created account has the `Admin` role and is already email-verified.
- The command is idempotent. If an account with that email exists, it is left unchanged (role, password and verification are not touched) and the command exits `0`.
- Exit codes: `0` success or already exists, `1` missing or invalid input or database failure, `2` unexpected extra arguments. The password is never printed.
- Run it once per environment, after the first deploy. Re-running is safe but has no effect.

## Docker

```bash
docker build -t auth .
docker run -p 5001:5001 --env-file .env auth
```

`Dockerfile` `sdk:10.0` `aspnet:10.0` `USER app` `HEALTHCHECK curl /health`.

## Troubleshooting

- `dotnet: command not found` → `mise trust` not run
- `NU1301 local source` → `mise run pack-shared`
- `password authentication failed` → `cd ../job-platform-infra && docker compose up -d && docker compose ps`
- `mise run verify` not 14 → re-run `mise run sync-env`

`feature/* → main` (see `job-platform-docs/.github/git-strategy.md`).

## Health, logging, quality

- `GET /health` — static liveness (`{"status":"ok","service":"auth"}`).
- `GET /health/ready` — readiness: Postgres (`AuthDbContext`) and Redis (only when `REDIS_URL` is set); `503` when a dependency is down.
- Rate limits (per IP, fixed window) and access-token revocation share the Redis at `REDIS_URL`. Production refuses to start without it. Access tokens last `Jwt:ExpiresMinutes` (default 15).
- The rate-limit connection times out after 500 ms and fails open with a warning, so a Redis outage does not hold login or registration for the default 5 s.
- Logging: Serilog, compact JSON on console outside Development. Every request gets an `X-Correlation-Id` (taken from the request if safe, generated otherwise, echoed in the response and attached to all log lines). Authorization headers/tokens are never logged.
- SonarCloud (optional): CI runs `dotnet-sonarscanner` only when the `SONAR_TOKEN` secret is available (skipped on fork PRs). Optional repo variables `SONAR_ORGANIZATION` (default `dut-pbl6-2026`) and `SONAR_PROJECT_KEY` (default `dut-pbl6-2026_job-platform-auth-svc`).
