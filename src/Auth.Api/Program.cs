using System.Text;
using System.Threading.RateLimiting;
using Auth.Api.Endpoints;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
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

// EF — Npgsql Connection Setup
var conn = builder.Configuration.GetConnectionString("AuthDb")
           ?? builder.Configuration["DATABASE_URL_AUTH"]
           ?? builder.Configuration["ConnectionStrings:AuthDb"];

if (string.IsNullOrWhiteSpace(conn))
{
    if (builder.Environment.IsProduction() || builder.Environment.IsStaging())
    {
        throw new InvalidOperationException("AuthDb connection string missing — set DATABASE_URL_AUTH or ConnectionStrings:AuthDb (PORT-05)");
    }
    conn = "Host=localhost;Port=5432;Database=job_platform_auth;Username=postgres;Password=__DEV_ONLY__";
}

builder.Services.AddDbContext<AuthDbContext>(o => o.UseNpgsql(conn));

// ForwardedHeaders
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
    o.ForwardLimit = 2; // Cloud Ingress + Gateway hops
});

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

// Application Services
builder.Services.AddSingleton<PasswordHasherService>();
builder.Services.AddSingleton<JwtTokenService>();

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
    });
builder.Services.AddAuthorization();

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
            detail = "Forgot password request limit exceeded. Please try again later."
        }, cancellationToken: token);
    };

    options.AddPolicy("forgot", httpContext =>
    {
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromHours(1),
                QueueLimit = 0
            });
    });
});

// OpenAPI & Health
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
app.UseExceptionHandler();

if (app.Environment.IsDevelopment() || app.Environment.IsStaging())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseForwardedHeaders();
app.UseCors("Default");
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

// Routes
app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "auth" }));
app.MapGet("/", () => Results.Ok(new { service = "auth", version = "0.1.0" }));
app.MapAuthEndpoints();

app.Run();

public partial class Program { }