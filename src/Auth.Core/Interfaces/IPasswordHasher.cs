namespace Auth.Core.Interfaces;

/// <summary>
/// Password hashing seam. Consumers call <see cref="Verify"/> on every login attempt,
/// including unknown accounts (against <see cref="DummyHash"/>), so response time does not
/// reveal whether an email is registered.
/// </summary>
public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string hash);

    /// <summary>A valid hash at the production work factor that matches no real password.</summary>
    string DummyHash { get; }
}
