using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;

namespace Auth.Tests;

public sealed class CustomAuthFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    // Same as PostgresFixture: rely on the module default pg_isready probe.
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine")
        .Build();

    public string ConnectionString => _container.GetConnectionString();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>));
            if (descriptor is not null)
                services.Remove(descriptor);
            services.AddDbContext<AuthDbContext>(o => o.UseNpgsql(ConnectionString));
            // Ensure Jwt secret is deterministic for CI
            services.Configure<SharedKernel.JwtOptions>(o =>
            {
                o.Secret = "dev-jwt-secret-change-me-32chars-min";
                o.Issuer = "job-platform";
                o.Audience = "job-platform";
                o.ExpiresMinutes = 60;
            });
        });
    }

    public async Task InitializeAsync()
    {
        // Generous timeout: CI image pulls on ubuntu-latest can stall.
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await _container.StartAsync(cts.Token);
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await db.Database.MigrateAsync(cts.Token);
    }

    public new async Task DisposeAsync()
    {
        await _container.DisposeAsync();
        await base.DisposeAsync();
    }

    public async Task ResetAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await db.Database.ExecuteSqlRawAsync("""
            DO $$
            DECLARE r RECORD;
            BEGIN
              FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename != '__EFMigrationsHistory') LOOP
                EXECUTE 'TRUNCATE TABLE "' || r.tablename || '" RESTART IDENTITY CASCADE;';
              END LOOP;
            END $$;
            """);
    }
}

public class AuthEndpointsTests : IClassFixture<CustomAuthFactory>, IAsyncLifetime
{
    private readonly CustomAuthFactory _factory;

    public AuthEndpointsTests(CustomAuthFactory factory)
    {
        _factory = factory;
    }

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Register_201_WithRelativeLocation()
    {
        var client = _factory.CreateClient();
        var req = new RegisterRequest($"user{Guid.NewGuid():N}@test.com", "SecureP@ss123", "Test User");
        var res = await client.PostAsJsonAsync("/api/auth/register", req);
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        var location = res.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.StartsWith("/api/users/", location);
        var body = await res.Content.ReadFromJsonAsync<RegisterResponse>();
        Assert.NotNull(body);
        Assert.NotEqual(Guid.Empty, body!.UserId);
        Assert.Equal("registered", body.Message);
        Assert.EndsWith(body.UserId.ToString(), location);
    }

    [Fact]
    public async Task Register_Duplicate_409()
    {
        var client = _factory.CreateClient();
        var req = new RegisterRequest($"dup{Guid.NewGuid():N}@test.com", "SecureP@ss123", "Dup");
        var first = await client.PostAsJsonAsync("/api/auth/register", req);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var second = await client.PostAsJsonAsync("/api/auth/register", req);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Login_200_ReturnsTokens()
    {
        var client = _factory.CreateClient();
        var email = $"login{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, "SecureP@ss123", "Login"));
        var loginRes = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, "SecureP@ss123"));
        Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);
        var body = await loginRes.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(body);
        Assert.False(string.IsNullOrWhiteSpace(body!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(body.RefreshToken));
        Assert.Equal(email.ToLowerInvariant(), body.User.Email.ToLowerInvariant());
    }

    [Fact]
    public async Task Login_WrongPassword_401()
    {
        var client = _factory.CreateClient();
        var email = $"bad{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, "SecureP@ss123", "Bad"));
        var bad = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, "wrong"));
        Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
    }

    [Fact]
    public async Task Health_ReturnsOk()
    {
        var client = _factory.CreateClient();
        var res = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadAsStringAsync();
        Assert.Contains("ok", body.ToLowerInvariant());
    }

    [Fact]
    public async Task Register_BlankFullName_400()
    {
        // [Required] allows whitespace; NonWhitespace must reject it.
        var client = _factory.CreateClient();
        var res = await client.PostAsJsonAsync(
            "/api/auth/register",
            new RegisterRequest("blank@test.com", "SecureP@ss123", "   "));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Login_BlankPassword_400()
    {
        var client = _factory.CreateClient();
        var res = await client.PostAsJsonAsync(
            "/api/auth/login",
            new LoginRequest("blank@test.com", "   "));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_6thWithinHour_429()
    {
        // Fine-grained policy "forgot": 5/h per IP. TestHost puts every
        // request in the same partition, and no other test touches this
        // endpoint, so the budget starts full and the 6th call is rejected.
        var client = _factory.CreateClient();
        HttpStatusCode? sixth = null;
        for (var i = 0; i < 6; i++)
        {
            var res = await client.PostAsJsonAsync(
                "api/auth/forgot-password",
                new ForgotPasswordRequest($"rl{i}@test.com"));
            if (i < 5)
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            else
                sixth = res.StatusCode;
        }
        Assert.Equal(HttpStatusCode.TooManyRequests, sixth);
    }
}
