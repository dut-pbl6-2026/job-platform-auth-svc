namespace Auth.Tests.Fixtures;

/// <summary>
/// One API host shared by a test class, with a rate-limit store the tests can clear. The class calls
/// <see cref="Reset"/> before each test, so the 5-per-IP-per-hour sign-up bucket starts empty every time.
/// </summary>
public sealed class CompanySignUpHost : IAsyncLifetime
{
    private readonly ResettableRateLimitCounterStore _limits = new();

    public CompanySignUpHost()
    {
        Factory = new RecordingAuthFactory { RateLimitStore = _limits };
    }

    public RecordingAuthFactory Factory { get; }

    public Task InitializeAsync() => Factory.InitializeAsync();

    public Task DisposeAsync() => Factory.DisposeAsync();

    public async Task Reset()
    {
        _limits.Clear();
        await Factory.ResetAsync();
    }
}
