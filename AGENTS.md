# AGENTS — job-platform-auth-svc

> Auth microservice. SRS: `job-platform-docs/docs/master-plan.md`, `docs/srs/en/{3-must-have-fr:AUTH-01,8-system-architecture,2-overall-description,6-nfr}`, `7-eir`. Git: `job-platform-docs/.github/git-strategy.md` (`feature/* → main`).

## Mise activation

Activate `mise` for bare `dotnet`/`infisical` without `mise exec`:

| Shell | Add to config file | Activate |
|-------|--------------------|----------|
| `bash` | `~/.bashrc` or `~/.bash_profile` | `eval "$(mise activate bash)"` |
| `zsh` | `~/.zshrc` | `eval "$(mise activate zsh)"` |
| `fish` | `~/.config/fish/config.fish` | `mise activate fish \| source` |
| `PowerShell` | `$PROFILE` | `mise activate pwsh \| Out-String \| Invoke-Expression` |

Agent uses `mise exec -- dotnet ...` / `mise exec -- infisical ...` due to non-interactive shell without `mise activate`; humans just use `dotnet` / `infisical` after `mise install`.

## Scope

`PBL6-12/13` MUST `AUTH-01` — `register/login/JWT/refresh/logout/forgot-reset` for Web+Mobile, `Port 5001` `net10.0` `YARP gateway`. Owner TM1 W1. DB `job_platform_auth`.

## Architecture — clean Api/Core/Infrastructure

```
src/Auth.Api            → Web API (Program.cs JWT Bearer + Swagger + /health + auto-migrate)
src/Auth.Core           → Domain (User, RefreshToken, PasswordResetToken : Entity)
src/Auth.Infrastructure → Data (AuthDbContext Npgsql, Migrations) + Services (JwtTokenService, PasswordHasherService)
tests/Auth.Tests        → xunit
AuthService.sln         → mise run build/test
```

Dependency: `Api → Infrastructure → Core → SharedKernel` (`PackageReference JobPlatform.SharedKernel 0.1.0` via `local-feed` + `nuget.config`, never `ProjectReference` per `master-plan.md:132`). `MAINT-01` clean arch, `Result<T>` for domain failures not exceptions.

## SRS mapping (AUTH-01)

- `POST /api/auth/register` `201 Created` `Location: /api/users/{id}` relative (RFC 9110) `{userId,message}` pwd `8+1upper+1num`, `POST /api/auth/login` `200 {accessToken,refreshToken,user}` `401/403`, `POST /api/auth/refresh` 7/30d SHA256 rotation reuse→revoke family, `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/forgot-password` 15min TTL 5/IP/h anti-enumeration, `POST /api/auth/reset-password` revokes all tokens, `GET/POST /api/companies` linking `companyId` FK tax_code verified.
- Gateway `GW-01` validates JWT then forwards `X-User-Id/Role`.

## JWT (SharedKernel JwtOptions)

`shared/JwtOptions.cs: SectionName=Jwt Secret≥32 Issuer=Audience=job-platform ExpiresMinutes=60`. `JwtTokenService.cs`: `HmacSha256` claims `sub`=`NameIdentifier`+`Email`+`Role`+`Jti`, expires `AddMinutes(60)`, `RandomNumberGenerator 64B Base64` for refresh, `SHA256 Hex Lower` for `TokenHash` (128 char). Fallback `dev-jwt-secret-change-me-32chars-min` **dev only**. Validate `ValidateIssuer/Audience/Lifetime/SigningKey ClockSkew=Zero` in `Program.cs`.

## Data — EF Core (NFR `6-nfr.md:SEC-03,MAINT`)

- `AuthDbContext: DbSet<User,RefreshToken,PasswordResetToken>` `UseNpgsql(ConnectionStrings:AuthDb / DATABASE_URL_AUTH)`. Fluent: `User Email unique 256 required FullName 128 Role 32 default User IsActive`, `RefreshToken TokenHash 128 required UserId FK ExpiresAt IsRevoked`, `PasswordResetToken same`.
- Migrations `src/Auth.Infrastructure/Data/Migrations/` (Init, FixTokenHash, snapshot) — `mise run ef-check` (`dotnet ef migrations has-pending-model-changes`) in PR+CI, auto-migrate on startup with `ILogger` (`Program.cs: Migrate()`).
- `NFR REL-01` retry 3 exp backoff, pooling `MaxPoolSize=20` via infra `env`.

## Security (SRS 6 `SEC-*`)

`SEC-03 bcrypt WorkFactor=12` via `BCrypt.Net-Next 4.0.3` in `PasswordHasherService.cs: Hash/Verify` only, `SEC-09 refresh SHA256 indexed daily purge`, `SEC-04 TLS1.2+`, `SEC-05 SQLi param + XSS encode + CSRF token`, `SEC-06 100/min IP+user`, `SEC-07 audit log auth`, `SEC-08 CV private` N/A for auth, `SEC-10 CORS trusted` via gateway.

## 2026 best practice (NFR `MAINT`)

- `dotnet 10.0.100` `net10.0` `nullable enable` `ImplicitUsings` file-scoped namespace, `ProblemDetails` + `UseExceptionHandler` + `ILogger` JSON `ERROR/WARN/INFO/DEBUG`, `GET /health` per `8-system-architecture.md`.
- `dotnet build --warnaserror` + `dotnet format --verify-no-changes` (mise `build/test/format`), `EF` alignment `EF10.0.4` + `Npgsql10.0.3` (MSB3277), coverage `>70%` `MAINT-02`.
- Never commit `.env` (`.gitignore`), `mise run sync-env` single source `../job-platform-infra/envs/.env.dev.example` (`DATABASE_URL_AUTH`, `JWT_SECRET`).

## Workflow

```bash
mise trust && mise install
mise run sync-env && mise run verify # 14
mise run build && mise run test && mise run format
mise run ef-check
mise run run  # http://localhost:5001/health → {"status":"ok"}
```

`feature/* → main` (PR template: Changes/How to verify/Checklist `mise run pack-shared` if `SharedKernel` bumped).
