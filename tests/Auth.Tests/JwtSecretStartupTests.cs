using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Auth.Tests;

public sealed class JwtSecretStartupTests
{
    [Theory]
    [InlineData("Production", "")]
    [InlineData("Production", "too-short-secret")]
    [InlineData("Staging", "")]
    [InlineData("Staging", "too-short-secret")]
    public void Startup_Fails_WhenSecretMissingOrShort_OutsideDevelopment(string environment, string secret)
    {
        using var factory = new SecretFactory(environment, secret);

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("Jwt:Secret", ex.ToString());
    }

    private sealed class SecretFactory(string environment, string secret) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            builder.UseSetting("Jwt:Secret", secret);
        }
    }
}
