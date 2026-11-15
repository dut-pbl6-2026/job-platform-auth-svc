using Auth.Infrastructure.Services;
using Microsoft.Extensions.Configuration;

namespace Auth.Tests;

public sealed class EmailSenderSelectionTests
{
    private const string Host = "smtp.example.test";
    private const string From = "no-reply@example.test";
    private const string User = "mailer@example.test";
    private const string Pass = "s3cret-value-do-not-log";

    [Fact]
    public void OutsideDevelopment_WithAllSmtpSettings_UsesSmtp()
    {
        // Covers Production, Staging and Testing: anything that is not Development.
        var kind = EmailSenderSelection.Resolve(isDevelopment: false, Config(
            ("SMTP_HOST", Host), ("SMTP_USER", User), ("SMTP_PASS", Pass), ("SMTP_FROM", From)));

        Assert.Equal(EmailSenderKind.Smtp, kind);
    }

    [Theory]
    [InlineData("SMTP_HOST")]
    [InlineData("SMTP_USER")]
    [InlineData("SMTP_PASS")]
    [InlineData("SMTP_FROM")]
    public void OutsideDevelopment_MissingAnySmtpSetting_Throws_NamingOnlyTheKey(string missingKey)
    {
        var settings = new Dictionary<string, string?>
        {
            ["SMTP_HOST"] = Host,
            ["SMTP_USER"] = User,
            ["SMTP_PASS"] = Pass,
            ["SMTP_FROM"] = From,
        };
        settings[missingKey] = "   ";

        var ex = Assert.Throws<InvalidOperationException>(() =>
            EmailSenderSelection.Resolve(isDevelopment: false, new ConfigurationBuilder().AddInMemoryCollection(settings).Build()));

        Assert.Contains(missingKey, ex.Message);
        Assert.DoesNotContain(Pass, ex.Message);
    }

    [Fact]
    public void OutsideDevelopment_WithLogOptIn_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => EmailSenderSelection.Resolve(isDevelopment: false, Config(
            ("EMAIL_SENDER", "log"), ("SMTP_HOST", Host), ("SMTP_USER", User), ("SMTP_PASS", Pass), ("SMTP_FROM", From))));

        Assert.Contains("only in Development", ex.Message);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void UnknownSenderValue_Throws(bool isDevelopment)
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            EmailSenderSelection.Resolve(isDevelopment, Config(("EMAIL_SENDER", "carrier-pigeon"), ("SMTP_HOST", Host), ("SMTP_FROM", From))));

        Assert.Contains("EMAIL_SENDER must be 'smtp' or 'log'", ex.Message);
    }

    [Fact]
    public void Development_WithNothingSet_Throws_NamingBothFixes()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => EmailSenderSelection.Resolve(isDevelopment: true, Config()));

        Assert.Contains("SMTP_HOST", ex.Message);
        Assert.Contains("EMAIL_SENDER=log", ex.Message);
    }

    [Fact]
    public void Development_WithLogOptIn_UsesLogger_WithoutSmtp()
    {
        var kind = EmailSenderSelection.Resolve(isDevelopment: true, Config(("EMAIL_SENDER", "log")));

        Assert.Equal(EmailSenderKind.Log, kind);
    }

    [Fact]
    public void Development_WithLogOptIn_AndSmtpHost_UsesLogger()
    {
        var kind = EmailSenderSelection.Resolve(isDevelopment: true, Config(("EMAIL_SENDER", "log"), ("SMTP_HOST", Host), ("SMTP_FROM", From)));

        Assert.Equal(EmailSenderKind.Log, kind);
    }

    [Fact]
    public void Development_WithSmtpHostAndFrom_UsesSmtp_WithoutUserOrPassword()
    {
        // MailHog takes no credentials.
        var kind = EmailSenderSelection.Resolve(isDevelopment: true, Config(("SMTP_HOST", "localhost"), ("SMTP_PORT", "1025"), ("SMTP_FROM", From)));

        Assert.Equal(EmailSenderKind.Smtp, kind);
    }

    [Fact]
    public void Development_WithSmtpHostButNoFrom_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            EmailSenderSelection.Resolve(isDevelopment: true, Config(("SMTP_HOST", "localhost"))));

        Assert.Contains("SMTP_FROM", ex.Message);
    }

    [Fact]
    public void Development_WithExplicitSmtp_AndNoHost_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            EmailSenderSelection.Resolve(isDevelopment: true, Config(("EMAIL_SENDER", "smtp"), ("SMTP_FROM", From))));

        Assert.Contains("SMTP_HOST", ex.Message);
    }

    [Fact]
    public void Development_WhitespaceSmtpHost_CountsAsUnset()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            EmailSenderSelection.Resolve(isDevelopment: true, Config(("SMTP_HOST", "  "), ("SMTP_FROM", From))));

        Assert.Contains("EMAIL_SENDER=log", ex.Message);
    }

    [Fact]
    public void Development_ExplicitSmtpInAnyCase_UsesSmtp()
    {
        var kind = EmailSenderSelection.Resolve(isDevelopment: true, Config(("EMAIL_SENDER", " SMTP "), ("SMTP_HOST", Host), ("SMTP_FROM", From)));

        Assert.Equal(EmailSenderKind.Smtp, kind);
    }

    [Theory]
    [InlineData("jane.doe@example.com", "j***@example.com")]
    [InlineData("a@b.c", "a***@b.c")]
    [InlineData("no-at-sign", "***")]
    [InlineData("", "<empty>")]
    [InlineData(null, "<empty>")]
    public void MaskEmail_KeepsOnlyFirstLetterAndDomain(string? email, string expected)
    {
        Assert.Equal(expected, LogRedaction.MaskEmail(email));
    }

    private static IConfiguration Config(params (string Key, string Value)[] settings) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(settings.ToDictionary(s => s.Key, s => (string?)s.Value))
            .Build();
}
