using System.Security.Cryptography;
using Auth.Core.Interfaces;

namespace Auth.Infrastructure.Services;

public class PasswordHasherService : IPasswordHasher
{
    private const int WorkFactor = 12;

    public PasswordHasherService()
    {
        // Random secret, hashed once per process: the dummy hash is fixed for the process
        // lifetime and matches no password a caller can know.
        DummyHash = Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    }

    public string DummyHash { get; }

    public string Hash(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
    }

    public bool Verify(string password, string hash)
    {
        return BCrypt.Net.BCrypt.Verify(password, hash);
    }
}
