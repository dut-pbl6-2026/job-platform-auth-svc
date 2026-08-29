# job-platform-auth-svc

.NET Web API Auth — **Vietnam Job Platform** (`pbl6`) under [`dut-pbl6-2026`](https://github.com/dut-pbl6-2026).

- **Tech:** `net10.0` `dotnet 10.0.100` `EF Core 10.0.4` `Npgsql 10.0.3` `JwtBearer 10.0.11`
- **Branch flow:** `feature/* → main` (see `job-platform-docs/.github/git-strategy.md`)
- **Jira:** `PBL6-12` `PBL6-13` `master-plan.md:150`

## Prerequisites

- `mise` `dotnet 10.0.100` `mise trust && mise install`
- `docker` for `postgres` (via `job-platform-infra`)
- `git` `gh`

## Clone

```bash
gh repo clone dut-pbl6-2026/job-platform-auth-svc
gh repo clone dut-pbl6-2026/job-platform-shared
gh repo clone dut-pbl6-2026/job-platform-infra
cd job-platform-auth-svc
```

## Setup

```bash
# 1. trust + tools
mise trust
mise install
dotnet --version  # 10.0.100
```

> Note: agent uses `mise exec -- dotnet ...` due to non-interactive shell without `mise activate`; humans just use `dotnet`.

# 2. env — from infra (single source)
../job-platform-infra/scripts/sync-env.sh dev  # or mise run sync-env in infra
# or
cp ../job-platform-infra/envs/.env.dev.example ../job-platform-infra/envs/.env.dev
cp ../job-platform-infra/envs/.env.dev .env
cat .env | grep DATABASE_URL_AUTH
ls ../job-platform-*/.env | wc -l  # 14 via infra

# 3. infra deps
cd ../job-platform-infra && docker compose up -d && docker compose ps  # postgres 5432 ready
cd ../job-platform-auth-svc
```

- `appsettings.json` `ConnectionStrings:AuthDb` fallback `DATABASE_URL_AUTH` `Host=localhost;Port=5432;Database=job_platform_auth`. `Jwt Secret` fallback `dev-jwt-secret-change-me-32chars-min` for local dev only (prod `JWT_SECRET` via `env`).

## Build

```bash
dotnet restore AuthService.sln  # nuget.config local-feed JobPlatform.SharedKernel 0.1.0
dotnet build AuthService.sln --warnaserror
dotnet format --verify-no-changes AuthService.sln
dotnet test AuthService.sln
dotnet ef migrations has-pending-model-changes --project src/Auth.Infrastructure --startup-project src/Auth.Api
```

> Note: agent uses `mise exec -- dotnet ...`; humans use `dotnet` directly.

- `nuget.config` `local-feed` `JobPlatform.SharedKernel 0.1.0` committed for `docker build`. To update shared: `dotnet pack ../job-platform-shared/src/SharedKernel -o ../job-platform-shared/artifacts && cp ../job-platform-shared/artifacts/*.nupkg local-feed/`.

## Run

```bash
dotnet run --project src/Auth.Api  # http://localhost:5001
curl http://localhost:5001/health     # {"status":"ok"}
curl http://localhost:5001/swagger    # swagger UI in Development
# EF auto-migrate on startup (see Program.cs UseExceptionHandler + ILogger)
```

> Note: agent uses `mise exec -- dotnet run ...`; humans use `dotnet run`.

- `POST /api/auth/register|login` in `PBL6-13` (next). `BCrypt workFactor 12` via `PasswordHasherService`.

## Docker

```bash
docker build -t auth .                # uses local-feed, no ../ shared context needed
docker run -p 5001:5001 --env-file .env auth
```

- `Dockerfile` `sdk:10.0` `aspnet:10.0` `USER app` `HEALTHCHECK curl /health` `EXPOSE 5001`.

## Troubleshooting

- `NU1301 local source doesn't exist` → `nuget.config` `local-feed` missing `*.nupkg` → re-pack shared.
- `NU1903 vulnerability` → bump `System.Security.Cryptography.Xml 10.0.11`.
- `MSB3277 Relational conflict` → keep `EF 10.0.4` with `Npgsql 10.0.3` (aligned).
- `password authentication failed` → `docker compose up -d` not ready, check `docker compose logs postgres`.
- `dotnet: command not found` → `mise trust` not run.
