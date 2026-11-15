using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

using Auth.Tests.Fixtures;

namespace Auth.Tests;

public sealed class StartupConfigurationTests
{

    [Fact]
    public void Startup_Fails_WhenConnectionStringMissing_EvenInDevelopment()
    {
        // Blank values override any DATABASE_URL_AUTH already present in the developer's environment.
        using var factory = new ConfigFactory("Development", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["DATABASE_URL_AUTH"] = "",
            ["ConnectionStrings:AuthDb"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("AuthDb connection string missing", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_InProduction_WhenRedisUrlMissing()
    {
        using var factory = new ConfigFactory("Production", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["ForwardedHeaders:KnownNetworks"] = "10.0.0.0/8",
            ["DATABASE_URL_AUTH"] = "Host=localhost;Database=unused",
            ["WEB_URL"] = "https://app.example.test",
            ["REDIS_URL"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("REDIS_URL missing", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_WhenWebUrlMissing_OutsideDevelopment()
    {
        using var factory = new ConfigFactory("Production", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["ForwardedHeaders:KnownNetworks"] = "10.0.0.0/8",
            ["DATABASE_URL_AUTH"] = "Host=localhost;Database=unused",
            ["WEB_URL"] = "",
            ["WebUrl"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("WEB_URL missing", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_InProduction_WhenSmtpSettingsMissing()
    {
        using var factory = new ConfigFactory("Production", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["ForwardedHeaders:KnownNetworks"] = "10.0.0.0/8",
            ["DATABASE_URL_AUTH"] = "Host=localhost;Database=unused",
            ["WEB_URL"] = "https://app.example.test",
            ["REDIS_URL"] = "localhost:6379",
            ["SMTP_HOST"] = "",
            ["SMTP_USER"] = "",
            ["SMTP_PASS"] = "",
            ["SMTP_FROM"] = "",
            ["EMAIL_SENDER"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("Auth email requires SMTP settings", ex.ToString());
        Assert.Contains("SMTP_HOST", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_InDevelopment_WhenNoSmtpAndNoLogOptIn()
    {
        using var factory = new ConfigFactory("Development", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["ConnectionStrings:AuthDb"] = "Host=localhost;Database=unused",
            ["DATABASE_URL_AUTH"] = "",
            ["SMTP_HOST"] = "",
            ["EMAIL_SENDER"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("EMAIL_SENDER=log", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_InProduction_WhenKnownNetworksMissing()
    {
        using var factory = new ConfigFactory("Production", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["DATABASE_URL_AUTH"] = "Host=localhost;Database=unused",
            ["WEB_URL"] = "https://app.example.test",
            ["ForwardedHeaders:KnownNetworks"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("ForwardedHeaders:KnownNetworks must list the gateway's network", ex.ToString());
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    [InlineData("10.0.0.0/8, 0.0.0.0/0")]
    public void Startup_Fails_InProduction_WhenKnownNetworksTrustsEveryPeer(string networks)
    {
        using var factory = new ConfigFactory("Production", new Dictionary<string, string?>
        {
            ["Jwt:SigningKeyPem"] = TestSigningKeys.PrivateKeyPemBase64,
            ["DATABASE_URL_AUTH"] = "Host=localhost;Database=unused",
            ["WEB_URL"] = "https://app.example.test",
            ["ForwardedHeaders:KnownNetworks"] = networks,
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("trusts every peer", ex.ToString());
    }

    private sealed class ConfigFactory(string environment, IDictionary<string, string?> settings) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            foreach (var (key, value) in settings)
                builder.UseSetting(key, value);
        }
    }
}
