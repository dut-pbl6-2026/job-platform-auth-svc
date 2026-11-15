using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http.Headers;
using Auth.Api.Security;
using Auth.Api.Bootstrap;
using Auth.Api.Endpoints;
using Auth.Api.Observability;
using Auth.Api.Networking;
using Auth.Api.RateLimiting;
using Auth.Core.Interfaces;
using Auth.Core.Security;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SharedKernel;
using StackExchange.Redis;
using OpenTelemetry.Metrics;

var builder = WebApplication.CreateBuilder(args);

// EF — Npgsql connection string comes from configuration only (no committed fallback).
// Development: set DATABASE_URL_AUTH (see README). Other environments: set it as well.
var conn = builder.Configuration.GetConnectionString("AuthDb")
           ?? builder.Configuration["DATABASE_URL_AUTH"];

// One-time admin bootstrap: `bootstrap-admin` runs the command and exits without starting the HTTP host.
if (AdminBootstrapCommand.IsInvoked(args))
    return await AdminBootstrapCommand.RunAsync(args, conn, Environment.GetEnvironmentVariable, Console.Out, Console.Error);

// Schema migration is a separate deploy step: `migrate` applies pending migrations and exits.
// The web host never migrates on startup.
if (MigrateCommand.IsInvoked(args))
    return await MigrateCommand.RunAsync(args, conn, Console.Out, Console.Error);

builder.AddObservability();

// Monitoring: expose OpenTelemetry metrics on /metrics (Prometheus scrape target).
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics
            .AddAspNetCoreInstrumentation()
            .AddHttpClientInstrumentation()
            .AddRuntimeInstrumentation()
            .AddPrometheusExporter();
    });

// Config
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
var jwt = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();
// Access tokens last 15 minutes unless Jwt:ExpiresMinutes (or Jwt__ExpiresMinutes) sets another value.
// The SharedKernel class default of 60 is never used by this service.
const int DefaultAccessTokenMinutes = 15;
builder.Services.Configure<JwtOptions>(o =>
{
    if (builder.Configuration["Jwt:ExpiresMinutes"] is null)
        o.ExpiresMinutes = DefaultAccessTokenMinutes;
});
if (jwt.ExpiresMinutes <= 0)
    throw new InvalidOperationException("Jwt:ExpiresMinutes must be a positive number of minutes");
// RS256 signing key (Jwt__SigningKeyPem). No default and no generated fallback, in every environment.
// Validators fetch the public half from /.well-known/jwks.json; the private key never leaves this process.
var signingKeys = JwtSigningKeys.FromConfiguration(builder.Configuration);
builder.Services.AddSingleton(signingKeys);

if (string.IsNullOrWhiteSpace(conn))
    throw new InvalidOperationException("AuthDb connection string missing — set DATABASE_URL_AUTH or ConnectionStrings__AuthDb");

builder.Services.AddDbContext<AuthDbContext>(o => o.UseNpgsql(conn));

// Verification and reset links point at the web app. A localhost default would send unusable
// links, so the URL is required everywhere except Development.
var webUrl = builder.Configuration["WEB_URL"] ?? builder.Configuration["WebUrl"];
if (string.IsNullOrWhiteSpace(webUrl) && !builder.Environment.IsDevelopment())
    throw new InvalidOperationException("WEB_URL missing — required for verification and password-reset links");


// ForwardedHeaders: trusted only from configured proxies. With none configured the
// middleware is not registered, because an empty KnownProxies list trusts every peer.
// Resolved eagerly: Production fails startup when ForwardedHeaders:KnownNetworks is empty or catch-all.
var forwardedProxyNetworks = ForwardedProxyTrust.ReadNetworks(builder.Configuration, builder.Environment.IsProduction());
if (forwardedProxyNetworks.Count > 0)
{
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.ForwardLimit = 1; // Right-most entry only: the entry the gateway appended for the client.
        ForwardedProxyTrust.Apply(o, forwardedProxyNetworks);
    });
}

// CORS
var corsOriginsRaw = builder.Configuration["CORS_ORIGINS"]
    ?? "http://localhost:5173,http://localhost:3000,https://jp-web.vercel.app,https://job-platform-web.vercel.app";
var origins = corsOriginsRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var originSet = new HashSet<string>(origins, StringComparer.OrdinalIgnoreCase);

builder.Services.AddCors(o => o.AddPolicy("Default", p => p
    .SetIsOriginAllowed(origin => originSet.Contains(origin))
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowCredentials()));

// Access-token revocation store (Redis when configured, in-memory for local dev)
var redisUrl = builder.Configuration["REDIS_URL"];
if (!string.IsNullOrWhiteSpace(redisUrl))
{
    var redisOptions = ConfigurationOptions.Parse(redisUrl);
    var redisPassword = builder.Configuration["REDIS_PASSWORD"];
    if (!string.IsNullOrWhiteSpace(redisPassword))
        redisOptions.Password = redisPassword;
    if (int.TryParse(builder.Configuration["REDIS_DB"], out var redisDb))
        redisOptions.DefaultDatabase = redisDb;
    redisOptions.AbortOnConnectFail = false;

    builder.Services.AddStackExchangeRedisCache(o => o.ConfigurationOptions = redisOptions);

    // Rate-limit counters share this Redis, so the limit holds across replicas. The middleware is built
    // with the pipeline, so this connection is opened at startup.
    builder.Services.AddSingleton<IRateLimitCounterStore>(_ =>
        new RedisRateLimitCounterStore(ConnectionMultiplexer.Connect(RateLimitRedisOptions.Create(redisOptions))));
}
else
{
    if (builder.Environment.IsProduction())
        throw new InvalidOperationException("REDIS_URL missing — required for access-token revocation and shared rate limits (PORT-05 fail-fast)");

    // Development and tests only: counters stay in this process. Production always requires REDIS_URL.
    builder.Services.AddDistributedMemoryCache();
    builder.Services.TryAddSingleton(TimeProvider.System);
    builder.Services.AddSingleton<IRateLimitCounterStore, LocalRateLimitCounterStore>();
}

// Application Services
builder.Services.AddSingleton<IPasswordHasher, PasswordHasherService>();
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddSingleton<ITokenRevocationStore, TokenRevocationStore>();

// Resolved here, not inside the factory below, so a missing mail setting stops startup instead of the first email.
var emailSenderKind = EmailSenderSelection.Resolve(builder.Environment.IsDevelopment(), builder.Configuration);
builder.Services.AddSingleton<IEmailSender>(sp => emailSenderKind == EmailSenderKind.Smtp
    ? new SmtpEmailSender(sp.GetRequiredService<IConfiguration>())
    : new LoggerEmailSender(sp.GetRequiredService<ILogger<LoggerEmailSender>>()));
// Auth emails are written to the outbox in the request's transaction and sent by this worker, so the
// response never waits for SMTP. Several replicas may run the worker: the dispatcher claims rows with a lease.
builder.Services.AddSingleton<EmailOutboxDispatcher>();
builder.Services.AddHostedService<EmailOutboxWorker>();

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IAdminService, AdminService>();
builder.Services.AddScoped<ICompanySignUpService, CompanySignUpService>();
// Free email providers that company sign-up rejects (AUTH-01-11). FREE_EMAIL_DOMAINS adds to the built-in list.
builder.Services.AddSingleton(new WorkEmailPolicy(
    (builder.Configuration["FREE_EMAIL_DOMAINS"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)));
builder.Services.AddHostedService<ExpiredTokenPurgeService>();

// Outbound Client: job-svc base URL (company stats and invite codes)
var jobBaseUrl = builder.Configuration["JOB_SERVICE_URL"] ?? builder.Configuration["COMPANY_SERVICE_URL"];
if (string.IsNullOrWhiteSpace(jobBaseUrl))
{
    if (builder.Environment.IsProduction() || builder.Environment.IsStaging())
        throw new InvalidOperationException("JOB_SERVICE_URL missing — required for invite-code and stats calls");
    jobBaseUrl = "http://localhost:5002";
}
jobBaseUrl = jobBaseUrl.Trim().TrimEnd('/') + "/";

var appServiceUrl = builder.Configuration["APP_SERVICE_URL"];
if (string.IsNullOrWhiteSpace(appServiceUrl))
{
    if (builder.Environment.IsProduction() || builder.Environment.IsStaging())
        throw new InvalidOperationException("APP_SERVICE_URL missing — required for admin stats aggregation");
    appServiceUrl = "http://localhost:5004";
}
appServiceUrl = appServiceUrl.Trim().TrimEnd('/') + "/"; // normalize trailing slash (AGENTS.md: BaseAddress must end with /)

// Per-caller tokens: auth-svc presents these to job-svc and app-svc (/api/internal/stats). Each
// callee accepts only the token issued to auth-svc. Outside Development a missing value fails startup.
var jobInternalToken = builder.Configuration["JOB_INTERNAL_TOKEN_FOR_AUTH"];
var appInternalToken = builder.Configuration["APP_INTERNAL_TOKEN_FOR_AUTH"];
// Accepted from notif-svc on GET /api/internal/users/{id}/email.
var notifCallerToken = builder.Configuration[InternalServiceAuth.NotifCallerTokenKey];
if (!builder.Environment.IsDevelopment() &&
    (string.IsNullOrWhiteSpace(jobInternalToken)
     || string.IsNullOrWhiteSpace(appInternalToken)
     || string.IsNullOrWhiteSpace(notifCallerToken)))
{
    throw new InvalidOperationException(
        "JOB_INTERNAL_TOKEN_FOR_AUTH, APP_INTERNAL_TOKEN_FOR_AUTH and AUTH_INTERNAL_TOKEN_FOR_NOTIF are required outside Development");
}

// Outbound Client: invite codes (SRS AUTH-01-09). Same per-caller token as the stats client.
// No resilience retry: redeem is not idempotent, so a retry after a lost response would report a valid code as used.
builder.Services
    .AddHttpClient<IInviteCodeClient, HttpInviteCodeClient>(c =>
    {
        c.BaseAddress = new Uri(jobBaseUrl, UriKind.Absolute);
        c.Timeout = TimeSpan.FromSeconds(5);
        if (!string.IsNullOrWhiteSpace(jobInternalToken))
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jobInternalToken);
    });

// Outbound Client: job-svc company directory (AUTH-01-10, AUTH-01-12). Same per-caller token; no retry, the
// create calls are not idempotent and a failed lookup fails the sign-up closed (503).
builder.Services
    .AddHttpClient<ICompanyDirectoryClient, HttpCompanyDirectoryClient>(c =>
    {
        c.BaseAddress = new Uri(jobBaseUrl, UriKind.Absolute);
        c.Timeout = TimeSpan.FromSeconds(5);
        if (!string.IsNullOrWhiteSpace(jobInternalToken))
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jobInternalToken);
    });

builder.Services
    .AddHttpClient<IJobServiceClient, JobServiceClient>(c =>
    {
        c.BaseAddress = new Uri(jobBaseUrl, UriKind.Absolute);
        c.Timeout = Timeout.InfiniteTimeSpan;
        if (!string.IsNullOrWhiteSpace(jobInternalToken))
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jobInternalToken);
    })
    .AddStandardResilienceHandler(o =>
    {
        o.AttemptTimeout.Timeout = TimeSpan.FromSeconds(3);
        o.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(10);
    });

builder.Services
    .AddHttpClient<IAppServiceClient, AppServiceClient>(c =>
    {
        c.BaseAddress = new Uri(appServiceUrl, UriKind.Absolute);
        c.Timeout = Timeout.InfiniteTimeSpan;
        if (!string.IsNullOrWhiteSpace(appInternalToken))
            c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", appInternalToken);
    })
    .AddStandardResilienceHandler(o =>
    {
        o.AttemptTimeout.Timeout = TimeSpan.FromSeconds(3);
        o.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(10);
    });

// Auth & JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            IssuerSigningKeys = signingKeys.VerificationKeys,
            TryAllIssuerSigningKeys = false,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
        o.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var principal = context.Principal;
                var subject = principal?.FindFirstValue(ClaimTypes.NameIdentifier)
                              ?? principal?.FindFirstValue(JwtRegisteredClaimNames.Sub);
                if (principal is null || !Guid.TryParse(subject, out var userId))
                    return;

                var issuedAt = GetIssuedAt(principal);
                var logger = context.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>()
                    .CreateLogger("TokenRevocation");

                try
                {
                    var store = context.HttpContext.RequestServices
                        .GetRequiredService<ITokenRevocationStore>();
                    var revokedAfter = await store.GetRevokedAfterAsync(
                        userId, context.HttpContext.RequestAborted);

                    if (revokedAfter is not null && issuedAt <= revokedAfter.Value.ToUnixTimeSeconds())
                    {
                        logger.LogWarning(
                            "Rejected revoked access token for user {UserId} (iat={IssuedAt}, revokedAfter={RevokedAfter})",
                            userId,
                            issuedAt,
                            revokedAfter.Value.ToUnixTimeSeconds());
                        context.Fail("Access token revoked");
                    }
                }
                catch (Exception ex)
                {
                    // Fail open on revocation-store outage: signature/lifetime were already validated.
                    logger.LogWarning(ex, "Token revocation check failed for user {UserId}", userId);
                }
            }
        };
    });
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy => policy.RequireAuthenticatedUser().RequireRole("Admin"));

// Rate limiting (fine-grained, per IP): policies are declared on endpoints, counted by IRateLimitCounterStore.
builder.Services.AddSingleton<IpRateLimiter>();

// OpenAPI & Health
// /health = static liveness (Render healthCheckPath). /health/ready = real dependency checks.
var healthChecks = builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("postgres", tags: [HealthCheckTags.Ready]);
if (!string.IsNullOrWhiteSpace(redisUrl))
    healthChecks.AddCheck<RedisHealthCheck>("redis", tags: [HealthCheckTags.Ready]);
builder.Services.AddProblemDetails();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement{{
        new OpenApiSecurityScheme{Reference = new OpenApiReference{Type = ReferenceType.SecurityScheme, Id = "Bearer"}}, Array.Empty<string>()}});
});

var app = builder.Build();

// Pipeline
app.UseObservability();
app.UseExceptionHandler();

if (app.Environment.IsDevelopment() || app.Environment.IsStaging())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (forwardedProxyNetworks.Count > 0)
    app.UseForwardedHeaders();
app.UseCors("Default");
app.UseMiddleware<IpRateLimitMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

// Monitoring: /metrics is meant for the internal scrape network; keep it off in
// Production unless METRICS_ENABLED=true (all services are publicly reachable).
if (app.Configuration.GetValue("METRICS_ENABLED", !app.Environment.IsProduction()))
{
    app.MapPrometheusScrapingEndpoint();
}

// Routes
app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "auth" }));
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = r => r.Tags.Contains(HealthCheckTags.Ready),
    ResponseWriter = HealthCheckResponseWriter.WriteAsync
});
app.MapGet("/", () => Results.Ok(new { service = "auth", version = "0.1.0" }));

// Token validation metadata for the other services. Public keys only; internal network, not routed by the gateway.
app.MapGet("/.well-known/openid-configuration", (HttpContext context) => Results.Ok(new
{
    issuer = jwt.Issuer,
    jwks_uri = $"{context.Request.Scheme}://{context.Request.Host}/.well-known/jwks.json",
}));
app.MapGet("/.well-known/jwks.json", () => Results.Ok(new { keys = signingKeys.JwksKeys() }));
app.MapAuthEndpoints();
app.MapAdminEndpoints();
app.MapInternalUserEndpoints();

app.Run();
return 0;

static long GetIssuedAt(ClaimsPrincipal principal)
{
    var raw = principal.FindFirst(JwtRegisteredClaimNames.Iat)?.Value;
    if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var issuedAt))
        return issuedAt;

    // Missing iat is treated as epoch 0 so an existing revocation entry still rejects the token.
    return 0;
}

public partial class Program { }