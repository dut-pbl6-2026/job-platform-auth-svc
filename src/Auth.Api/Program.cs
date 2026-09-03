using System.Text;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Auth.Api.Endpoints;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SharedKernel;

var builder = WebApplication.CreateBuilder(args);

// Config
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
var jwt = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrEmpty(jwt.Secret) || jwt.Secret.Length < 32)
{
    if (builder.Environment.IsProduction())
        throw new InvalidOperationException("JWT Secret must be >=32 chars via JWT__Secret / Jwt:Secret (PORT-05 fail-fast)");
    jwt.Secret = "dev-jwt-secret-change-me-32chars-min";
}

// EF — Use InMemory for Testing env to avoid Npgsql/InMemory dual provider conflict
// PORT-05: no hardcoded secrets in source — Production requires env, dev falls back to placeholder
var conn = builder.Configuration.GetConnectionString("AuthDb")
           ?? builder.Configuration["DATABASE_URL_AUTH"]
           ?? builder.Configuration["ConnectionStrings:AuthDb"];
if (string.IsNullOrWhiteSpace(conn))
{
    if (builder.Environment.IsProduction() || builder.Environment.IsStaging())
        throw new InvalidOperationException("AuthDb connection string missing — set DATABASE_URL_AUTH or ConnectionStrings:AuthDb (PORT-05)");
    // Dev-only placeholder (overridden by env/sync-env, not committed as secret)
    conn = "Host=localhost;Port=5432;Database=job_platform_auth;Username=postgres;Password=__DEV_ONLY__";
}
if (builder.Environment.IsEnvironment("Testing"))
{
    var dbName = $"auth-test-{Guid.NewGuid()}";
    builder.Services.AddDbContext<AuthDbContext>(o => o.UseInMemoryDatabase(dbName));
}
else
{
    builder.Services.AddDbContext<AuthDbContext>(o => o.UseNpgsql(conn));
}

// ForwardedHeaders — required behind gateway/Render YARP so RemoteIpAddress reflects client IP (SEC-06)
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

// CORS — trust gateway + Vercel + localhost dev + wildcard preview *-jp-web.vercel.app
var corsOriginsRaw = builder.Configuration["CORS_ORIGINS"] ?? "http://localhost:5173,http://localhost:3000,https://jp-web.vercel.app,https://job-platform-web.vercel.app";
var origins = corsOriginsRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var originSet = new HashSet<string>(origins, StringComparer.OrdinalIgnoreCase);
var previewRegex = new Regex(@"^https://([a-z0-9-]+\.)*jp-web(-\w+)?\.vercel\.app$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
builder.Services.AddCors(o => o.AddPolicy("Default", p => p
    .SetIsOriginAllowed(origin =>
        originSet.Contains(origin) ||
        previewRegex.IsMatch(origin) ||
        (origin.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && origin.EndsWith(".vercel.app", StringComparison.OrdinalIgnoreCase) && origin.Contains("jp-web", StringComparison.OrdinalIgnoreCase)))
    .AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

// Services
builder.Services.AddSingleton<PasswordHasherService>();
builder.Services.AddSingleton<JwtTokenService>();
// MailKit SmtpEmailSender when SMTP_HOST configured, else Logger fallback (local/dev)
builder.Services.AddSingleton<IEmailSender>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
    var smtpHost = config["SMTP_HOST"] ?? config["EMAIL_SMTP_HOST"];
    if (!string.IsNullOrWhiteSpace(smtpHost))
        return new SmtpEmailSender(
            sp.GetRequiredService<ILogger<SmtpEmailSender>>(),
            config);
    return new LoggerEmailSender(
        loggerFactory.CreateLogger<LoggerEmailSender>(),
        config);
});
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddHostedService<ExpiredTokenPurgeService>();

// Company validation HttpClient (Option A — no DB duplication)
var jobBaseUrl = builder.Configuration["JOB_SERVICE_URL"] ?? builder.Configuration["COMPANY_SERVICE_URL"];
if (string.IsNullOrWhiteSpace(jobBaseUrl))
{
    if (builder.Environment.IsProduction() || builder.Environment.IsStaging())
        throw new InvalidOperationException("JOB_SERVICE_URL missing — required for Recruiter companyId validation (PORT-05)");
    jobBaseUrl = "http://localhost:5002";
}
builder.Services.AddHttpClient<ICompanyValidationClient, HttpCompanyValidationClient>(c => c.BaseAddress = new Uri(jobBaseUrl));

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
            ClockSkew = TimeSpan.Zero
        };
    });
builder.Services.AddAuthorization();

// Rate limiting SEC-06: global 100/min per IP + forgot 5/h per IP (partition via X-Forwarded-For when behind proxy)
static string GetRateLimitPartitionKey(HttpContext httpContext)
{
    var xff = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
    if (!string.IsNullOrWhiteSpace(xff))
    {
        var first = xff.Split(',')[0].Trim();
        if (!string.IsNullOrWhiteSpace(first)) return first;
    }
    return httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("global", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: GetRateLimitPartitionKey(httpContext),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
    options.AddPolicy("forgot", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: GetRateLimitPartitionKey(httpContext),
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromHours(1),
                QueueLimit = 0
            }));
});

// ProblemDetails + Swagger + health
builder.Services.AddProblemDetails();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement{{
        new Microsoft.OpenApi.Models.OpenApiSecurityScheme{Reference=new Microsoft.OpenApi.Models.OpenApiReference{Type=Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id="Bearer"}}, new string[]{}}});
});

var app = builder.Build();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseForwardedHeaders();
app.UseCors("Default");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "auth" }));
app.MapGet("/", () => Results.Ok(new { service = "auth", version = "0.1.0" }));
app.MapAuthEndpoints();

// Auto-migrate on startup (skip for InMemory Testing)
using (var scope = app.Services.CreateScope())
{
    var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Program");
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    if (!db.Database.IsInMemory())
    {
        try
        {
            db.Database.Migrate();
            logger.LogInformation("DB migrated successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "DB migrate failed");
            if (app.Environment.IsDevelopment()) throw;
        }
    }
    else
    {
        db.Database.EnsureCreated();
        logger.LogInformation("InMemory DB ensured created (Testing)");
    }
}

app.Run();

public partial class Program { }
