using System.Net;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

// Needs the shared Postgres container: a host that starts runs its startup migrations.
[Collection(PostgresCollection.Name)]
public sealed class DevelopmentEmailStartupTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Development_WithExplicitLogOptIn_Starts_AndUsesLoggerSender()
    {
        using var factory = new DevelopmentFactory(postgres.ConnectionString, emailSender: "log");

        using var client = factory.CreateClient();
        var health = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.IsType<LoggerEmailSender>(factory.Services.GetRequiredService<IEmailSender>());
    }

    [Fact]
    public async Task Development_WithSmtpHost_Starts_AndUsesSmtpSender()
    {
        using var factory = new DevelopmentFactory(postgres.ConnectionString, emailSender: null, smtpHost: "localhost");

        using var client = factory.CreateClient();
        var health = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.IsType<SmtpEmailSender>(factory.Services.GetRequiredService<IEmailSender>());
    }

    private sealed class DevelopmentFactory(string connectionString, string? emailSender, string? smtpHost = null) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:AuthDb", connectionString);
            builder.UseSetting("EMAIL_SENDER", emailSender ?? "");
            builder.UseSetting("SMTP_HOST", smtpHost ?? "");
            builder.UseSetting("SMTP_FROM", smtpHost is null ? "" : "no-reply@job-platform.local");
        }
    }
}
