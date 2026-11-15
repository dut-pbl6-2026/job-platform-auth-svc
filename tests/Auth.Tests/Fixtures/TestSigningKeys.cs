using System.Security.Cryptography;
using System.Text;
using Auth.Infrastructure.Services;

namespace Auth.Tests.Fixtures;

/// <summary>
/// RSA key pair generated once per test process. Nothing is committed: the PEM exists only in memory.
/// </summary>
public static class TestSigningKeys
{
    private static readonly Lazy<RSA> Key = new(() => RSA.Create(2048));

    /// <summary>Value for <c>Jwt:SigningKeyPem</c>: base64 of the PKCS#8 PEM private key.</summary>
    public static string PrivateKeyPemBase64 { get; } =
        Convert.ToBase64String(Encoding.UTF8.GetBytes(Key.Value.ExportPkcs8PrivateKeyPem()));

    /// <summary>Key set the service would build from <see cref="PrivateKeyPemBase64"/>.</summary>
    public static JwtSigningKeys Keys { get; } = JwtSigningKeys.Create(Key.Value, []);

    /// <summary>A second key the service never signs with: tokens from it must be rejected.</summary>
    public static RSA ForeignKey { get; } = RSA.Create(2048);
}
