using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using System.Net.Http.Headers;
using Auth.Api.Bootstrap;
using Auth.Api.Endpoints;
using Auth.Api.Observability;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
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
if (builder.Environment.IsDevelopment() && string.IsNullOrEmpty(jwt.Secret))
    jwt.Secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
if (string.IsNullOrEmpty(jwt.Secret) || jwt.Secret.Length < 32)
    throw new InvalidOperationException("Jwt:Secret must be at least 32 characters (set Jwt__Secret outside Development)");
builder.Services.PostConfigure<JwtOptions>(o => o.Secret = jwt.Secret);

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
var knownProxies = (builder.Configuration["ForwardedHeaders:KnownProxies"] ?? string.Empty)
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Select(static proxy => IPAddress.Parse(proxy))
    .ToArray();
if (knownProxies.Length > 0)
{
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Clear();
        foreach (var proxy in knownProxies)
            o.KnownProxies.Add(proxy);
        o.ForwardLimit = 2; // Cloud Ingress + Gateway hops
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
}
else
{
    if (builder.Environment.IsProduction())
        throw new InvalidOperationException("REDIS_URL missing — required for access-token revocation (PORT-05 fail-fast)");

    builder.Services.AddDistributedMemoryCache();
}

// Application Services
builder.Services.AddSingleton<IPasswordHasher, PasswordHasherService>();
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddSingleton<ITokenRevocationStore, TokenRevocationStore>();

builder.Services.AddSingleton<IEmailSender>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
    var smtpHost = config["SMTP_HOST"] ?? config["EMAIL_SMTP_HOST"];

    if (!string.IsNullOrWhiteSpace(smtpHost))
        return new SmtpEmailSender(sp.GetRequiredService<ILogger<SmtpEmailSender>>(), config);

    return new LoggerEmailSender(loggerFactory.CreateLogger<LoggerEmailSender>(), config);
});

builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IAdminService, AdminService>();
builder.Services.AddHostedService<ExpiredTokenPurgeService>();

// Outbound Client: Company Validation
var jobBaseUrl = builder.Configuration["JOB_SERVICE_URL"] ?? builder.Configuration["COMPANY_SERVICE_URL"];
if (string.IsNullOrWhiteSpace(jobBaseUrl))
{
    if (builder.Environment.IsProduction() || builder.Environment.IsStaging())
        throw new InvalidOperationException("JOB_SERVICE_URL missing — required for Recruiter companyId validation (PORT-05)");
    jobBaseUrl = "http://localhost:5002";
}
jobBaseUrl = jobBaseUrl.Trim().TrimEnd('/') + "/";

builder.Services
    .AddHttpClient<ICompanyValidationClient, HttpCompanyValidationClient>(c =>
    {
        c.BaseAddress = new Uri(jobBaseUrl, UriKind.Absolute);
        c.Timeout = Timeout.InfiniteTimeSpan;
    })
    .AddStandardResilienceHandler(o =>
    {
        o.AttemptTimeout.Timeout = TimeSpan.FromSeconds(3);
        o.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(10);
    });

var appServiceUrl = builder.Configuration["APP_SERVICE_URL"];
if (string.IsNullOrWhiteSpace(appServiceUrl))
{
    if (builder.Environment.IsProduction() || builder.Environment.IsStaging())
        throw new InvalidOperationException("APP_SERVICE_URL missing — required for admin stats aggregation");
    appServiceUrl = "http://localhost:5004";
}
appServiceUrl = appServiceUrl.Trim().TrimEnd('/') + "/"; // normalize trailing slash (AGENTS.md: BaseAddress must end with /)

var jobInternalToken = builder.Configuration["JOB_SERVICE_INTERNAL_TOKEN"];
var appInternalToken = builder.Configuration["APP_SERVICE_INTERNAL_TOKEN"];
if ((builder.Environment.IsProduction() || builder.Environment.IsStaging()) &&
    (string.IsNullOrWhiteSpace(jobInternalToken) || string.IsNullOrWhiteSpace(appInternalToken)))
{
    throw new InvalidOperationException(
        "JOB_SERVICE_INTERNAL_TOKEN and APP_SERVICE_INTERNAL_TOKEN are required for admin stats aggregation");
}

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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Secret)),
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

// Rate Limiting (Fine-Grained)
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.OnRejected = async (context, token) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)Math.Max(1, retryAfter.TotalSeconds)).ToString();
        }

        context.HttpContext.Response.ContentType = "application/json";
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            status = 429,
            title = "Too Many Requests",
            detail = "Too many requests. Please try again later."
        }, cancellationToken: token);
    };

    AddIpFixedWindowPolicy(options, "login", permitLimit: 10, window: TimeSpan.FromMinutes(15));
    AddIpFixedWindowPolicy(options, "register", permitLimit: 10, window: TimeSpan.FromHours(1));
    AddIpFixedWindowPolicy(options, "refresh", permitLimit: 30, window: TimeSpan.FromMinutes(15));
    AddIpFixedWindowPolicy(options, "reset", permitLimit: 10, window: TimeSpan.FromHours(1));
    AddIpFixedWindowPolicy(options, "forgot", permitLimit: 5, window: TimeSpan.FromHours(1));
    AddIpFixedWindowPolicy(options, "verify", permitLimit: 10, window: TimeSpan.FromMinutes(15));
});

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

// DB Auto-Migration
using (var scope = app.Services.CreateScope())
{
    var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Program");
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

    try
    {
        db.Database.Migrate();
        logger.LogInformation("DB migrated successfully");
    }
    catch (Exception ex)
    {
        logger.LogCritical(ex, "DB migration failed — shutting down application");
        throw;
    }
}

// Pipeline
app.UseObservability();
app.UseExceptionHandler();

if (app.Environment.IsDevelopment() || app.Environment.IsStaging())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (knownProxies.Length > 0)
    app.UseForwardedHeaders();
app.UseCors("Default");
app.UseRateLimiter();

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
app.MapAuthEndpoints();
app.MapAdminEndpoints();
app.MapInternalUserEndpoints();

app.Run();
return 0;

static void AddIpFixedWindowPolicy(RateLimiterOptions options, string name, int permitLimit, TimeSpan window) =>
    options.AddPolicy(name, httpContext => RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = window,
            QueueLimit = 0
        }));

static long GetIssuedAt(ClaimsPrincipal principal)
{
    var raw = principal.FindFirst(JwtRegisteredClaimNames.Iat)?.Value;
    if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var issuedAt))
        return issuedAt;

    // Missing iat is treated as epoch 0 so an existing revocation entry still rejects the token.
    return 0;
}

public partial class Program { }