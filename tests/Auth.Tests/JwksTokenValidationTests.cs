using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Tests;

/// <summary>
/// The JWKS that validators fetch must hold public RSA keys only, and auth-svc must accept exactly
/// the RS256 tokens it signs: HS256, unknown keys and tokens without a kid are refused.
/// </summary>
public sealed class JwksTokenValidationTests : IClassFixture<RecordingAuthFactory>
{
    private static readonly string[] PrivateMembers = ["d", "p", "q", "dp", "dq", "qi"];
    private readonly RecordingAuthFactory _factory;

    public JwksTokenValidationTests(RecordingAuthFactory factory) => _factory = factory;

    [Fact]
    public async Task Jwks_PublishesOnlyThePublicSigningKey()
    {
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync("/.well-known/jwks.json");

        using var doc = JsonDocument.Parse(body);
        var keys = doc.RootElement.GetProperty("keys");
        Assert.Equal(1, keys.GetArrayLength());
        var key = keys[0];
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal(TestSigningKeys.Keys.Signing.KeyId, key.GetProperty("kid").GetString());
        foreach (var member in PrivateMembers)
            Assert.False(key.TryGetProperty(member, out _), $"JWKS must not expose private member '{member}'");
    }

    [Fact]
    public async Task Discovery_PointsValidatorsAtTheJwks()
    {
        var client = _factory.CreateClient();

        using var doc = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));

        Assert.Equal("job-platform", doc.RootElement.GetProperty("issuer").GetString());
        Assert.EndsWith("/.well-known/jwks.json", doc.RootElement.GetProperty("jwks_uri").GetString());
    }

    [Fact]
    public async Task AccessToken_IsAcceptedByAuthService()
    {
        var token = IssueToken();

        var res = await GetMeAsync(token);

        Assert.NotEqual(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Hs256Token_IsRejected()
    {
        var secret = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(48));
        var token = Sign(new SigningCredentials(secret, SecurityAlgorithms.HmacSha256), kid: null);

        Assert.Equal(HttpStatusCode.Unauthorized, (await GetMeAsync(token)).StatusCode);
    }

    [Fact]
    public async Task Token_SignedWithAnUnknownKey_IsRejected_EvenWithOurKid()
    {
        var foreign = new RsaSecurityKey(TestSigningKeys.ForeignKey) { KeyId = TestSigningKeys.Keys.Signing.KeyId };
        var token = Sign(new SigningCredentials(foreign, SecurityAlgorithms.RsaSha256), kid: foreign.KeyId);

        Assert.Equal(HttpStatusCode.Unauthorized, (await GetMeAsync(token)).StatusCode);
    }

    [Fact]
    public async Task Token_WithoutKid_IsRejected_EvenWhenSignedByOurKey()
    {
        var ours = new RsaSecurityKey(TestSigningKeys.Keys.Signing.Rsa) { KeyId = null };
        var token = Sign(new SigningCredentials(ours, SecurityAlgorithms.RsaSha256), kid: null);

        Assert.Equal(HttpStatusCode.Unauthorized, (await GetMeAsync(token)).StatusCode);
    }

    [Fact]
    public async Task Token_WithUnknownKid_IsRejected_EvenWhenSignedByOurKey()
    {
        var ours = new RsaSecurityKey(TestSigningKeys.Keys.Signing.Rsa) { KeyId = "not-published" };
        var token = Sign(new SigningCredentials(ours, SecurityAlgorithms.RsaSha256), kid: "not-published");

        Assert.Equal(HttpStatusCode.Unauthorized, (await GetMeAsync(token)).StatusCode);
    }

    [Fact]
    public void ValidatorBuiltFromJwks_AcceptsOurToken()
    {
        // What a validator does with the published document: rebuild keys from JWKS JSON, then validate.
        var jwksJson = JsonSerializer.Serialize(new { keys = TestSigningKeys.Keys.JwksKeys() });
        var published = new JsonWebKeySet(jwksJson).Keys;
        var token = IssueToken();

        var result = new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidIssuer = "job-platform",
            ValidAudience = "job-platform",
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            IssuerSigningKeys = published,
            TryAllIssuerSigningKeys = false,
            ClockSkew = TimeSpan.Zero,
        }, out _);

        Assert.NotNull(result.FindFirst(ClaimTypes.NameIdentifier));
    }

    private string IssueToken() => _factory.Services.GetRequiredService<JwtTokenService>()
        .GenerateAccessToken(Guid.NewGuid(), "jwks-test@test.com", "User");

    private Task<HttpResponseMessage> GetMeAsync(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client.GetAsync("/api/auth/me");
    }

    private static string Sign(SigningCredentials credentials, string? kid)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
        };
        var header = new JwtHeader(credentials);
        if (kid is null)
            header.Remove("kid");
        var token = new JwtSecurityToken(header, new JwtPayload("job-platform", "job-platform", claims,
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(10)));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
