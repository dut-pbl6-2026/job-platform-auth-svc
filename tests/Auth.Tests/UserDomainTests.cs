using Auth.Core.Entities;

namespace Auth.Tests;

public class UserDomainTests
{
    private static User CreateUser() =>
        new("user@test.com", "hash", "Test User");

    [Fact]
    public void Deactivate_SetsIsActiveFalse()
    {
        var user = CreateUser();

        user.Deactivate();

        Assert.False(user.IsActive);
    }

    [Fact]
    public void Deactivate_IsIdempotent()
    {
        var user = CreateUser();
        user.Deactivate();

        user.Deactivate();

        Assert.False(user.IsActive);
    }

    [Fact]
    public void Activate_SetsIsActiveTrue()
    {
        var user = CreateUser();
        user.Deactivate();

        user.Activate();

        Assert.True(user.IsActive);
    }

    [Fact]
    public void Activate_IsIdempotent()
    {
        var user = CreateUser();
        user.Deactivate();

        user.Activate();
        user.Activate();

        Assert.True(user.IsActive);
    }
}
