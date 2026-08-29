using Auth.Infrastructure.Services;

namespace Auth.Tests;

public class PasswordHasherTests
{
    private readonly PasswordHasherService _hasher = new();

    [Fact]
    public void Hash_Verify_Roundtrip()
    {
        var pwd = "SecureP@ss123";
        var hash = _hasher.Hash(pwd);
        Assert.True(_hasher.Verify(pwd, hash));
        Assert.False(_hasher.Verify("wrong", hash));
    }

    [Fact]
    public void Hash_Uses_WorkFactor12()
    {
        var hash = _hasher.Hash("test");
        // BCrypt hash format $2a$12$... cost 12
        Assert.Contains("$12$", hash);
    }
}
