using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Auth.Tests;

public sealed class StartupConfigurationTests
{
    private const string ValidSecret = "unit-test-signing-key-0123456789abcdef";

    [Fact]
    public void Startup_Fails_WhenConnectionStringMissing_EvenInDevelopment()
    {
        // Blank values override any DATABASE_URL_AUTH already present in the developer's environment.
        using var factory = new ConfigFactory("Development", new Dictionary<string, string?>
        {
            ["Jwt:Secret"] = ValidSecret,
            ["DATABASE_URL_AUTH"] = "",
            ["ConnectionStrings:AuthDb"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("AuthDb connection string missing", ex.ToString());
    }

    [Fact]
    public void Startup_Fails_WhenWebUrlMissing_OutsideDevelopment()
    {
        using var factory = new ConfigFactory("Production", new Dictionary<string, string?>
        {
            ["Jwt:Secret"] = ValidSecret,
            ["DATABASE_URL_AUTH"] = "Host=localhost;Database=unused",
            ["WEB_URL"] = "",
            ["WebUrl"] = "",
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("WEB_URL missing", ex.ToString());
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
