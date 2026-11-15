using System.Security.Cryptography;
using System.Text;
using Auth.Tests.Fixtures;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Auth.Tests;

public sealed class JwtSigningKeyStartupTests
{
    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void Startup_Fails_WhenSigningKeyMissing_InEveryEnvironment(string environment)
    {
        using var factory = new KeyFactory(environment, new Dictionary<string, string?> { ["Jwt:SigningKeyPem"] = "" });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("Jwt:SigningKeyPem", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_WhenSigningKeyIsNotBase64()
    {
        using var factory = new KeyFactory("Production", new Dictionary<string, string?> { ["Jwt:SigningKeyPem"] = "not base64 !!" });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("base64", ex.ToString());
        Assert.DoesNotContain("not base64 !!", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_WhenSigningKeyIsNotAPemKey()
    {
        using var factory = new KeyFactory("Production", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("plain text, not a key")),
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("not a valid RSA private key PEM", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_WhenSigningKeyIsPublicOnly()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ExportSubjectPublicKeyInfoPem()));
        using var factory = new KeyFactory("Production", new Dictionary<string, string?> { ["Jwt:SigningKeyPem"] = publicPem });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("must contain a private RSA key", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_WhenSigningKeyIsShorterThan2048Bits()
    {
        using var rsa = RSA.Create(1024);
        var pem = Convert.ToBase64String(Encoding.UTF8.GetBytes(rsa.ExportPkcs8PrivateKeyPem()));
        using var factory = new KeyFactory("Production", new Dictionary<string, string?> { ["Jwt:SigningKeyPem"] = pem });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("at least 2048 bits", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_WhenPreviousPublicKeyIsInvalid()
    {
        using var factory = new KeyFactory("Development", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["Jwt:PreviousPublicKeys:0"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("garbage")),
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("Jwt:PreviousPublicKeys", ex.ToString());
    }

    private sealed class KeyFactory(string environment, IDictionary<string, string?> settings) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            foreach (var (key, value) in settings)
                builder.UseSetting(key, value);
        }
    }
}
