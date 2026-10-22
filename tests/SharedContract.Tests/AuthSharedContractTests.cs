using SharedKernel;

namespace SharedContract.Tests;

public class AuthSharedContractTests
{
    [Fact]
    public void JwtOptions_PreservesAuthConfigurationContract()
    {
        var options = new JwtOptions
        {
            Secret = "contract-test-secret-at-least-32-characters",
            Issuer = "auth-contract-issuer",
            Audience = "auth-contract-audience",
            ExpiresMinutes = 60
        };

        Assert.Equal("Jwt", JwtOptions.SectionName);
        Assert.Equal(
            "contract-test-secret-at-least-32-characters",
            options.Secret);
        Assert.Equal("auth-contract-issuer", options.Issuer);
        Assert.Equal("auth-contract-audience", options.Audience);
        Assert.Equal(60, options.ExpiresMinutes);
    }

    [Fact]
    public void ResultSuccess_PreservesAuthReturnValue()
    {
        var userId = Guid.Parse(
            "11111111-1111-1111-1111-111111111111");

        var result = Result<Guid>.Success(userId);

        Assert.True(result.IsSuccess);
        Assert.Equal(userId, result.Value);
        Assert.Null(result.Error);
    }

    [Fact]
    public void ResultFailure_PreservesAuthError()
    {
        var result = Result<Guid>.Failure("Invalid credentials");

        Assert.False(result.IsSuccess);
        Assert.Equal("Invalid credentials", result.Error);
    }

    [Fact]
    public void Entity_PreservesIdentityAndTimestampContract()
    {
        var entity = new AuthConsumerEntity();

        Assert.NotEqual(Guid.Empty, entity.Id);
        Assert.Equal(DateTimeKind.Utc, entity.CreatedAt.Kind);
        Assert.Equal(DateTimeKind.Utc, entity.UpdatedAt.Kind);

        var timestamp = new DateTime(
            2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        entity.SetUpdatedAt(timestamp);
        entity.Touch();

        Assert.True(entity.UpdatedAt > timestamp);
        Assert.Equal(DateTimeKind.Utc, entity.UpdatedAt.Kind);
    }

    private sealed class AuthConsumerEntity : Entity
    {
        public void SetUpdatedAt(DateTime timestamp)
        {
            UpdatedAt = timestamp;
        }
    }
}