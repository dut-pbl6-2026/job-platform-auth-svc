using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Infrastructure.Services;

/// <summary>
/// RSA key material for access tokens. One private key signs; the public halves of that key and of
/// any previous keys are published in the JWKS so validators keep accepting tokens during a rotation.
/// Only public parameters ever leave this type.
/// </summary>
public sealed class JwtSigningKeys
{
    /// <summary>Configuration key (env <c>Jwt__SigningKeyPem</c>): base64 of a PKCS#8 PEM RSA private key.</summary>
    public const string SigningKeyPemSetting = "Jwt:SigningKeyPem";

    /// <summary>Configuration section (env <c>Jwt__PreviousPublicKeys__N</c>): base64 of SPKI PEM public keys.</summary>
    public const string PreviousPublicKeysSection = "Jwt:PreviousPublicKeys";

    /// <summary>Minimum RSA modulus size accepted for signing.</summary>
    public const int MinimumKeyBits = 2048;

    private JwtSigningKeys(RSA privateKey, IReadOnlyList<RsaSecurityKey> verificationKeys, IReadOnlyList<PublishedKey> published)
    {
        Signing = new RsaSecurityKey(privateKey) { KeyId = published[0].Kid };
        VerificationKeys = verificationKeys;
        Published = published;
    }

    /// <summary>Signing key. Its <see cref="SecurityKey.KeyId"/> is written to the token header as <c>kid</c>.</summary>
    public RsaSecurityKey Signing { get; }

    /// <summary>Public keys that token validation accepts: the signing key first, then the previous keys.</summary>
    public IReadOnlyList<RsaSecurityKey> VerificationKeys { get; }

    /// <summary>Public metadata of every published key, in the order they appear in the JWKS.</summary>
    public IReadOnlyList<PublishedKey> Published { get; }

    /// <summary>Loads the keys from configuration. Throws naming the setting (never its value) when invalid.</summary>
    public static JwtSigningKeys FromConfiguration(IConfiguration configuration)
    {
        var pemBase64 = configuration[SigningKeyPemSetting];
        if (string.IsNullOrWhiteSpace(pemBase64))
            throw new InvalidOperationException($"{SigningKeyPemSetting} is required (base64 of a PKCS#8 RSA private key PEM; env Jwt__SigningKeyPem).");

        var privateKey = RSA.Create();
        try
        {
            privateKey.ImportFromPem(DecodePem(pemBase64, SigningKeyPemSetting));
            RequirePrivate(privateKey);
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            privateKey.Dispose();
            throw new InvalidOperationException($"{SigningKeyPemSetting} is not a valid RSA private key PEM.", ex);
        }
        catch
        {
            privateKey.Dispose();
            throw;
        }

        if (privateKey.KeySize < MinimumKeyBits)
        {
            privateKey.Dispose();
            throw new InvalidOperationException($"{SigningKeyPemSetting} must be an RSA key of at least {MinimumKeyBits} bits.");
        }

        var previous = new List<RSA>();
        try
        {
            var previousPems = configuration.GetSection(PreviousPublicKeysSection).Get<string[]>() ?? [];
            foreach (var entry in previousPems)
            {
                var rsa = RSA.Create();
                previous.Add(rsa);
                try
                {
                    rsa.ImportFromPem(DecodePem(entry, PreviousPublicKeysSection));
                }
                catch (Exception ex) when (ex is not InvalidOperationException)
                {
                    throw new InvalidOperationException($"{PreviousPublicKeysSection} contains an entry that is not a valid RSA public key PEM.", ex);
                }
            }
            return Create(privateKey, previous);
        }
        finally
        {
            foreach (var rsa in previous)
                rsa.Dispose();
        }
    }

    /// <summary>Builds the key set from in-memory keys. The caller keeps ownership of the RSA instances.</summary>
    public static JwtSigningKeys Create(RSA privateKey, IEnumerable<RSA> previousPublicKeys)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var signingParameters = privateKey.ExportParameters(includePrivateParameters: false);
        var signing = Describe(signingParameters);

        var published = new List<PublishedKey> { signing };
        var verification = new List<RsaSecurityKey> { PublicKey(signingParameters, signing.Kid) };
        foreach (var previous in previousPublicKeys)
        {
            var parameters = previous.ExportParameters(includePrivateParameters: false);
            var described = Describe(parameters);
            if (published.Any(p => p.Kid == described.Kid))
                continue;
            published.Add(described);
            verification.Add(PublicKey(parameters, described.Kid));
        }

        return new JwtSigningKeys(privateKey, verification, published);
    }

    /// <summary>Public JWKS document: <c>{"keys":[...]}</c> with RSA public members only.</summary>
    public IReadOnlyList<IReadOnlyDictionary<string, string>> JwksKeys() =>
        Published.Select(p => (IReadOnlyDictionary<string, string>)new Dictionary<string, string>
        {
            ["kty"] = "RSA",
            ["use"] = "sig",
            ["alg"] = "RS256",
            ["kid"] = p.Kid,
            ["n"] = p.N,
            ["e"] = p.E,
        }).ToList();

    private static RsaSecurityKey PublicKey(RSAParameters parameters, string kid) =>
        new(new RSAParameters { Modulus = parameters.Modulus, Exponent = parameters.Exponent }) { KeyId = kid };

    private static PublishedKey Describe(RSAParameters parameters)
    {
        var n = Base64Url(parameters.Modulus!);
        var e = Base64Url(parameters.Exponent!);
        // RFC 7638 thumbprint: required members only, lexicographic order, no whitespace.
        var canonical = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";
        var kid = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        return new PublishedKey(kid, n, e);
    }

    private static void RequirePrivate(RSA rsa)
    {
        try
        {
            if (rsa.ExportParameters(includePrivateParameters: true).D is not null)
                return;
        }
        catch (CryptographicException)
        {
            // A public-only key cannot export its private parameters.
        }
        throw new InvalidOperationException($"{SigningKeyPemSetting} must contain a private RSA key.");
    }

    private static string DecodePem(string value, string setting)
    {
        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(value.Trim()));
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"{setting} must be base64-encoded PEM text.", ex);
        }
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Public metadata of one key.</summary>
    public sealed record PublishedKey(string Kid, string N, string E);
}
