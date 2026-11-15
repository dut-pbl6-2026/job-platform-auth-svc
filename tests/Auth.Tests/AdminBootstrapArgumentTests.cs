using Auth.Api.Bootstrap;

namespace Auth.Tests;

public class AdminBootstrapArgumentTests
{
    [Fact]
    public void IsInvoked_FalseWithoutArguments()
    {
        Assert.False(AdminBootstrapCommand.IsInvoked([]));
    }

    [Theory]
    [InlineData("--urls=http://localhost:5001")]
    [InlineData("bootstrap")]
    [InlineData("--bootstrap-admin")]
    public void IsInvoked_FalseForOtherArguments(string arg)
    {
        Assert.False(AdminBootstrapCommand.IsInvoked([arg]));
    }

    [Fact]
    public void IsInvoked_TrueWhenCommandIsFirstArgument()
    {
        Assert.True(AdminBootstrapCommand.IsInvoked(["bootstrap-admin"]));
    }

    [Fact]
    public async Task RunAsync_RejectsExtraArguments_WithoutTouchingTheDatabase()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        // A null connection string would fail with a different message; the usage check must come first.
        var exitCode = await AdminBootstrapCommand.RunAsync(
            ["bootstrap-admin", "--force"], connectionString: null, _ => null, stdout, stderr);

        Assert.Equal(2, exitCode);
        Assert.Contains("Usage: bootstrap-admin", stderr.ToString());
        Assert.Equal(string.Empty, stdout.ToString());
    }
}
