using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

public class AuthEndpointsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AuthEndpointsTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureServices(services =>
            {
                // Ensure Jwt secret is deterministic for CI
                services.Configure<SharedKernel.JwtOptions>(o =>
                {
                    o.Secret = "dev-jwt-secret-change-me-32chars-min";
                    o.Issuer = "job-platform";
                    o.Audience = "job-platform";
                    o.ExpiresMinutes = 60;
                });
            });
        });
    }

    private HttpClient CreateClientWithDb(out IServiceScope scope)
    {
        var client = _factory.CreateClient();
        scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        db.Database.EnsureCreated();
        return client;
    }

    [Fact]
    public async Task Register_201_WithRelativeLocation()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        // Use fresh factory client to avoid cross-test db pollution; recreate factory per test would be cleaner
        // For simplicity create new factory with isolated db
        var isolatedFactory = _factory.WithWebHostBuilder(b => b.UseEnvironment("Testing"));
        var client = isolatedFactory.CreateClient();
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
        var isolatedFactory = _factory.WithWebHostBuilder(b => b.UseEnvironment("Testing"));
        var client = isolatedFactory.CreateClient();
        var req = new RegisterRequest("dup@test.com", "SecureP@ss123", "Dup");
        var first = await client.PostAsJsonAsync("/api/auth/register", req);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var second = await client.PostAsJsonAsync("/api/auth/register", req);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Login_200_ReturnsTokens()
    {
        var isolatedFactory = _factory.WithWebHostBuilder(b => b.UseEnvironment("Testing"));
        var client = isolatedFactory.CreateClient();
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
        var isolatedFactory = _factory.WithWebHostBuilder(b => b.UseEnvironment("Testing"));
        var client = isolatedFactory.CreateClient();
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
}
