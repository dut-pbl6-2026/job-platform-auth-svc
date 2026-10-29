using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Entities;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

public class AdminEndpointsTests : IClassFixture<CustomAuthFactory>, IAsyncLifetime
{
    private readonly CustomAuthFactory _factory;

    public AdminEndpointsTests(CustomAuthFactory factory)
    {
        _factory = factory;
    }

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(Guid AdminId, Guid UserId)> SeedAsync(bool userActive = true, bool secondAdmin = false)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

        var admin = new User("admin@test.com", "secret-hash", "Admin User", "Admin");
        var user = new User("user@test.com", "secret-hash", "Normal User");
        if (!userActive) user.Deactivate();

        db.Users.AddRange(admin, user);

        if (secondAdmin)
            db.Users.Add(new User("admin2@test.com", "secret-hash", "Admin Two", "Admin"));

        await db.SaveChangesAsync();
        return (admin.Id, user.Id);
    }

    private static HttpRequestMessage AdminRequest(
        HttpMethod method,
        string path,
        Guid adminId,
        string role = "Admin",
        object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-User-Id", adminId.ToString());
        request.Headers.Add("X-User-Role", role);
        if (body is not null)
            request.Content = JsonContent.Create(body);
        return request;
    }

    [Fact]
    public async Task GetUsers_Admin_Returns200_AndNoPasswordHash()
    {
        var (adminId, _) = await SeedAsync();
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Get, "/api/admin/users", adminId));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("passwordHash", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret-hash", json);
        Assert.Contains("user@test.com", json);

        using var doc = JsonDocument.Parse(json);
        Assert.Equal(2, doc.RootElement.GetProperty("data").GetArrayLength());
        Assert.Equal(2, doc.RootElement.GetProperty("pagination").GetProperty("totalItems").GetInt32());
    }

    [Fact]
    public async Task GetUsers_NonAdmin_Returns403()
    {
        var (adminId, _) = await SeedAsync();
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Get, "/api/admin/users", adminId, role: "User"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetUsers_MissingUserId_Returns401()
    {
        var client = _factory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/admin/users");
        request.Headers.Add("X-User-Role", "Admin");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetUsers_SpoofedAdminHeaderForNonAdminActor_Returns403()
    {
        var (_, userId) = await SeedAsync();
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Get, "/api/admin/users", userId, role: "Admin"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetUser_NotFound_Returns404()
    {
        var (adminId, _) = await SeedAsync();
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Get, $"/api/admin/users/{Guid.NewGuid()}", adminId));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Deactivate_Self_Returns403()
    {
        var (adminId, _) = await SeedAsync();
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Patch, $"/api/admin/users/{adminId}/deactivate", adminId, body: new { }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Deactivate_AdminTarget_Returns403()
    {
        var (adminId, _) = await SeedAsync(secondAdmin: true);
        Guid admin2Id;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            admin2Id = (await db.Users.SingleAsync(u => u.Email == "admin2@test.com")).Id;
        }

        var client = _factory.CreateClient();
        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Patch, $"/api/admin/users/{admin2Id}/deactivate", adminId, body: new { }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Deactivate_User_Returns204_RevokesTokensAndWritesAudit()
    {
        var (adminId, userId) = await SeedAsync();
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.RefreshTokens.Add(new RefreshToken(userId, new string('a', 64), DateTime.UtcNow.AddDays(7)));
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();
        var response = await client.SendAsync(
            AdminRequest(
                HttpMethod.Patch,
                $"/api/admin/users/{userId}/deactivate",
                adminId,
                body: new { reason = "spam account" }));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.False((await verifyDb.Users.SingleAsync(u => u.Id == userId)).IsActive);
        Assert.True((await verifyDb.RefreshTokens.SingleAsync()).IsRevoked);
        var audit = await verifyDb.AuditLogs.SingleAsync();
        Assert.Equal("ADMIN_DEACTIVATE_USER", audit.Action);
        Assert.Equal("spam account", audit.Reason);

        var cache = verifyScope.ServiceProvider.GetRequiredService<IDistributedCache>();
        var revokedAfter = await cache.GetStringAsync(TokenRevocationStore.KeyFor(userId));
        Assert.False(string.IsNullOrWhiteSpace(revokedAfter));
    }

    [Fact]
    public async Task Deactivate_ReasonTooLong_Returns422()
    {
        var (adminId, userId) = await SeedAsync();
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(
                HttpMethod.Patch,
                $"/api/admin/users/{userId}/deactivate",
                adminId,
                body: new { reason = new string('x', 501) }));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    [Fact]
    public async Task Activate_User_Returns204_AndActivates()
    {
        var (adminId, userId) = await SeedAsync(userActive: false);
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Patch, $"/api/admin/users/{userId}/activate", adminId));

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        using var verifyScope = _factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.True((await verifyDb.Users.SingleAsync(u => u.Id == userId)).IsActive);
    }

    [Fact]
    public async Task Activate_NotFound_Returns404()
    {
        var (adminId, _) = await SeedAsync();
        var client = _factory.CreateClient();

        var response = await client.SendAsync(
            AdminRequest(HttpMethod.Patch, $"/api/admin/users/{Guid.NewGuid()}/activate", adminId));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
