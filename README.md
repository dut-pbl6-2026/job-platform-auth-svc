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
curl -i -X POST http://localhost:5001/api/auth/register -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"SecureP@ss123","fullName":"Hoai"}' # 201 Created Location: /api/users/{id}
curl -X POST http://localhost:5001/api/auth/login -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"SecureP@ss123"}' # 200 {accessToken,refreshToken,user}
```

`auto-migrate` on startup, `UseExceptionHandler` + `ILogger`.

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

## Deploy (Render Free jp-auth — TM1 Hoai)
- Service: `jp-auth` `https://jp-auth.onrender.com` `5001` `health /health`
- Env (Render Dashboard): `JWT_SECRET` `DATABASE_URL_AUTH=Supabase pooled` `CORS_ORIGINS=https://jp-web.vercel.app`
- Hook: `GH Secrets RENDER_DEPLOY_HOOK_AUTH = https://api.render.com/deploy/srv-xxx?key=yyy` → `push main` auto `curl hook` + smoke `curl https://jp-auth.onrender.com/health`
- Local: `docker compose -f ../job-platform-infra/docker-compose.yml up --build auth`
