namespace Approov.Validation.Tests;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Approov.Validation;
using Microsoft.IdentityModel.Tokens;
using StructuredFieldValues;

internal static class ApproovRequestValidatorTestData
{
    public const string TestSecretBase64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
    private const string TestPrivateKey = "MHcCAQEEIHWZ2Ueq6odQNG+aaYmEbp7C6nujYNGr7nYKK2jqQ2asoAoGCCqGSM49AwEHoUQDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";
    public static readonly string ValidPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";

    public static ApproovSignedRequest BuildSignedRequest(
        string? token,
        byte[]? body = null,
        bool includeContentDigest = false)
    {
        body ??= Array.Empty<byte>();
        var headers = BaseHeaders(token);
        if (includeContentDigest)
        {
            headers["Content-Digest"] = new[] { $"sha-256=:{Convert.ToBase64String(SHA256.HashData(body))}:" };
        }

        var unsigned = new ApproovSignedRequest("GET", "https", "api.example.com", "/token", "?param=value", headers, body);
        headers["Signature"] = new[] { $"install=:{SignCanonicalMessage(BuildCanonicalMessage(unsigned))}:" };

        return new ApproovSignedRequest("GET", "https", "api.example.com", "/token", "?param=value", headers, body);
    }

    public static string CreateToken(
        DateTime? expires = null,
        string? secretBase64 = null,
        string? pay = null,
        string? ipk = null)
    {
        var secret = Convert.FromBase64String(secretBase64 ?? TestSecretBase64);
        var claims = new List<Claim> { new("did", "ExampleDevice") };

        if (!string.IsNullOrWhiteSpace(pay))
        {
            claims.Add(new Claim("pay", pay));
        }

        if (!string.IsNullOrWhiteSpace(ipk))
        {
            claims.Add(new Claim("ipk", ipk));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            NotBefore = DateTime.UtcNow.AddHours(-1),
            IssuedAt = DateTime.UtcNow.AddHours(-1),
            Expires = expires ?? DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256)
        };

        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    private static Dictionary<string, IReadOnlyList<string>> BaseHeaders(string? token)
    {
        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30;
        var expires = created + 600;
        var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            [ApproovFunctionRequestBuilder.OriginalMethodHeader] = new[] { "GET" },
            [ApproovFunctionRequestBuilder.OriginalSchemeHeader] = new[] { "https" },
            [ApproovFunctionRequestBuilder.OriginalHostHeader] = new[] { "api.example.com" },
            [ApproovFunctionRequestBuilder.OriginalPathHeader] = new[] { "/token" },
            [ApproovFunctionRequestBuilder.OriginalQueryHeader] = new[] { "?param=value" },
            ["Signature-Input"] = new[] { $"install=(\"@method\" \"@target-uri\" \"approov-token\");alg=\"ecdsa-p256-sha256\";created={created};expires={expires}" }
        };

        if (!string.IsNullOrWhiteSpace(token))
        {
            headers["Approov-Token"] = new[] { token };
        }

        return headers;
    }

    private static string BuildCanonicalMessage(ApproovSignedRequest request)
    {
        var parseError = SfvParser.ParseDictionary(request.GetHeaderValue("Signature-Input"), out var dictionary);
        if (parseError.HasValue || dictionary is null || !dictionary.TryGetValue("install", out var signatureInputItem))
        {
            throw new InvalidOperationException(parseError?.Message ?? "Invalid Signature-Input test fixture.");
        }

        var components = (IReadOnlyList<ParsedItem>)signatureInputItem.Value!;
        var lines = new List<string>();

        foreach (var component in components)
        {
            var identifier = (string)component.Value!;
            var value = identifier switch
            {
                "@method" => request.Method,
                "@target-uri" => request.TargetUri,
                _ => request.GetHeaderValue(identifier)
            };

            lines.Add($"{StructuredFieldFormatter.SerializeItem(component)}: {value}");
        }

        lines.Add("\"@signature-params\": " + StructuredFieldFormatter.SerializeInnerList(components, signatureInputItem.Parameters));
        return string.Join('\n', lines);
    }

    private static string SignCanonicalMessage(string canonicalMessage)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(Convert.FromBase64String(TestPrivateKey), out _);
        return Convert.ToBase64String(ecdsa.SignData(
            Encoding.UTF8.GetBytes(canonicalMessage),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
}
