# job-platform-auth-svc

Auth service for **Vietnam Job Platform** (`pbl6`) — `dut-pbl6-2026`.

Handles `register` `login` `JWT` `refresh` for Web + Mobile. `Port 5001` `net10.0`.

## Overview

- `src/Auth.Api` — Web API `Program.cs` `JWT Bearer` `Swagger` `health`
- `src/Auth.Core` — `User` `RefreshToken` entities
- `src/Auth.Infrastructure` — `AuthDbContext` `Npgsql` `Migrations` `JwtTokenService` `PasswordHasherService` `BCrypt 12`
- `tests` — `xunit` `PasswordHasher` tests
- `local-feed` — `JobPlatform.SharedKernel 0.1.0` via `nuget.config` (no `../` project ref)

## Quick Start

```bash
mkdir -p ~/projects/personal/job-platform && cd ~/projects/personal/job-platform
gh repo clone dut-pbl6-2026/job-platform-auth-svc
gh repo clone dut-pbl6-2026/job-platform-shared
gh repo clone dut-pbl6-2026/job-platform-infra
cd job-platform-auth-svc
mise trust && mise install && dotnet --version  # 10.0.100
../job-platform-infra/scripts/sync-env.sh dev
cd ../job-platform-infra && docker compose up -d && docker compose ps
cd ../job-platform-auth-svc && dotnet run --project src/Auth.Api  # http://localhost:5001/health
```

## Prerequisites

- `mise` https://mise.jdx.dev + `eval "$(mise activate bash)"`
- `dotnet 10.0.100` via `mise`
- `docker` + `docker compose v2`
- `git` `gh`

## Clone

```bash
gh repo clone dut-pbl6-2026/job-platform-auth-svc
gh repo clone dut-pbl6-2026/job-platform-shared
gh repo clone dut-pbl6-2026/job-platform-infra
cd job-platform-auth-svc
```

Need all 3: `auth` code, `shared` `SharedKernel` pack, `infra` `postgres` + `.env`.

## Setup

### 1. Tools

```bash
mise trust
mise install
dotnet --version  # 10.0.100
```

### 2. Env (single source: infra)

```bash
../job-platform-infra/scripts/sync-env.sh dev
cat .env | grep DATABASE_URL_AUTH
```

Creates `.env` from `../job-platform-infra/envs/.env.dev.example`. Prod uses `JWT_SECRET` env.

### 3. Postgres

```bash
cd ../job-platform-infra
docker compose up -d
docker compose ps  # postgres 5432 healthy
cd ../job-platform-auth-svc
```

## Build

```bash
dotnet restore AuthService.sln
dotnet build AuthService.sln --warnaserror
dotnet format --verify-no-changes AuthService.sln
dotnet test AuthService.sln
```

Short aliases: `mise run build` `mise run test` `mise run format` `make build` `make test`.

EF check (long):

```bash
dotnet ef migrations has-pending-model-changes --project src/Auth.Infrastructure --startup-project src/Auth.Api
```

Short: `mise run ef-check` or `make ef-check`.

To update SharedKernel: `mise run pack-shared` or `make pack-shared` (packs `../job-platform-shared` to `local-feed`).

## Run

```bash
dotnet run --project src/Auth.Api
curl http://localhost:5001/health     # {"status":"ok"}
curl http://localhost:5001/swagger    # Swagger UI (Development)
```

- `auto-migrate` on startup with `UseExceptionHandler` + `ILogger`.
- `appsettings.json` fallback `Host=localhost;Port=5432;Database=job_platform_auth`.

## Docker

```bash
docker build -t auth .
docker run -p 5001:5001 --env-file .env auth
```

`Dockerfile` `sdk:10.0` `aspnet:10.0` `USER app` `HEALTHCHECK curl /health`.

## Troubleshooting

- `dotnet: command not found` → `mise trust` not run.
- `NU1301 local source` → `local-feed/*.nupkg` missing → `mise run pack-shared`.
- `password authentication failed` → `docker compose up -d` not ready → `docker compose logs postgres`.
- `MSB3277 Relational` → `EF 10.0.4` + `Npgsql 10.0.3` must stay aligned.
- `NU1903 vulnerability` → already fixed `Xml 10.0.11`.

> Note: agent uses `mise exec -- dotnet ...` due to non-interactive shell; humans use `dotnet` directly after `mise install`.

## Contributing

`feature/* → main` (see `job-platform-docs/.github/git-strategy.md`). `Jira PBL6-12/13`.
