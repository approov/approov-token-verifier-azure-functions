namespace Approov.Validation.Tests;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Approov.Validation;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using StructuredFieldValues;

public sealed class ApproovRequestValidatorTests
{
    private const string TestSecretBase64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
    private const string TestPrivateKey = "MHcCAQEEIHWZ2Ueq6odQNG+aaYmEbp7C6nujYNGr7nYKK2jqQ2asoAoGCCqGSM49AwEHoUQDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";
    private static readonly string ValidPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJSm4DMcivAwvhM+KNce2C/X26cj3oGyUwWVUPuNuZHtd2qyVsM+0g7qX73Qh0Of6fn10AApLnl8vRQsvx94fZQ==";

    [Fact]
    public void Validate_WithValidTokenAndSignature_ReturnsValid()
    {
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey));
        var result = CreateValidator().Validate(request);

        Assert.True(result.IsValid);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal("ExampleDevice", result.DeviceId);
        Assert.True(result.MessageSignatureVerified);
    }

    [Fact]
    public void Validate_WithoutToken_ReturnsUnauthorized()
    {
        var request = BuildSignedRequest(token: null);
        var result = CreateValidator().Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("missing_approov_token", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithExpiredToken_ReturnsUnauthorized()
    {
        var request = BuildSignedRequest(CreateToken(expires: DateTime.UtcNow.AddMinutes(-1), ipk: ValidPublicKey));
        var result = CreateValidator().Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("expired_approov_token", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithWrongTokenSignature_ReturnsUnauthorized()
    {
        var request = BuildSignedRequest(CreateToken(secretBase64: Convert.ToBase64String(Encoding.UTF8.GetBytes("wrong-secret-wrong-secret-wrong-secret")), ipk: ValidPublicKey));
        var result = CreateValidator().Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_approov_token_signature", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithMatchingTokenBinding_ReturnsValid()
    {
        var authorization = "Bearer customer-token";
        var pay = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(authorization)));
        var request = BuildSignedRequest(CreateToken(pay: pay, ipk: ValidPublicKey), ("Authorization", authorization));
        var result = CreateValidator(bindingHeaders: new[] { "Authorization" }).Validate(request);

        Assert.True(result.IsValid);
        Assert.True(result.TokenBindingVerified);
    }

    [Fact]
    public void Validate_WithMissingTokenBindingHeader_ReturnsBadRequest()
    {
        var token = CreateToken(pay: Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("Bearer customer-token"))), ipk: ValidPublicKey);
        var request = BuildSignedRequest(token);
        var result = CreateValidator(bindingHeaders: new[] { "Authorization" }).Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("missing_token_binding_header", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithMismatchedTokenBinding_ReturnsUnauthorized()
    {
        var token = CreateToken(pay: Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("Bearer original-token"))), ipk: ValidPublicKey);
        var request = BuildSignedRequest(token, ("Authorization", "Bearer changed-token"));
        var result = CreateValidator(bindingHeaders: new[] { "Authorization" }).Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_token_binding", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithInvalidSignature_ReturnsUnauthorized()
    {
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey));
        var tampered = WithHeader(request, "Signature", "install=:AAAA:");

        var result = CreateValidator().Validate(tampered);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithoutSignatureInput_ReturnsUnauthorized()
    {
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey));
        var headers = request.Headers.ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);
        headers.Remove("Signature-Input");
        var missing = new ApproovSignedRequest(request.Method, request.Scheme, request.Host, request.Path, request.Query, headers, request.Body, request.OriginalUrl);

        var result = CreateValidator().Validate(missing);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("missing_message_signature", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithMissingInstallationPublicKey_ReturnsUnauthorized()
    {
        var request = BuildSignedRequest(CreateToken());
        var result = CreateValidator().Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("missing_installation_public_key", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithUnsupportedSignatureAlgorithm_ReturnsUnauthorized()
    {
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey));
        var alteredInput = request.GetHeaderValue("Signature-Input").Replace("ecdsa-p256-sha256", "rsa-v1_5-sha256", StringComparison.Ordinal);
        var altered = WithHeader(request, "Signature-Input", alteredInput);

        var result = CreateValidator().Validate(altered);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithStaleSignature_ReturnsUnauthorized()
    {
        var created = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds();
        var expires = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey), created: created, expires: expires);

        var result = CreateValidator().Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithFutureSignature_ReturnsUnauthorized()
    {
        var created = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var expires = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds();
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey), created: created, expires: expires);

        var result = CreateValidator().Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithUnsupportedSignedComponent_ReturnsUnauthorized()
    {
        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30;
        var expires = created + 600;
        var signatureInput = $"install=(\"@unknown-component\");alg=\"ecdsa-p256-sha256\";created={created};expires={expires}";
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey), signatureInput: signatureInput);

        var result = CreateValidator().Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Fact]
    public void Validate_WithBodyTooLarge_ReturnsPayloadTooLarge()
    {
        var request = BuildSignedRequest(CreateToken(ipk: ValidPublicKey), body: new byte[8], includeContentDigest: false);
        var result = CreateValidator(maxBodyBytes: 4).Validate(request);

        Assert.False(result.IsValid);
        Assert.Equal(413, result.StatusCode);
    }

    [Fact]
    public void Validate_WithContentDigestMismatch_ReturnsUnauthorized()
    {
        var token = CreateToken(ipk: ValidPublicKey);
        var request = BuildSignedRequest(token, body: Encoding.UTF8.GetBytes("{\"ok\":true}"), includeContentDigest: true);
        var tampered = new ApproovSignedRequest(request.Method, request.Scheme, request.Host, request.Path, request.Query, request.Headers, Encoding.UTF8.GetBytes("{\"ok\":false}"), request.OriginalUrl);

        var result = CreateValidator().Validate(tampered);

        Assert.False(result.IsValid);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Fact]
    public void FunctionRequestBuilder_MissingMetadata_ReturnsBadRequest()
    {
        var (request, error) = ApproovFunctionRequestBuilder.FromMirroredRequest(
            new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase),
            Array.Empty<byte>(),
            1024);

        Assert.Null(request);
        Assert.NotNull(error);
        Assert.Equal(400, error!.StatusCode);
    }

    [Fact]
    public void FunctionRequestBuilder_UsesOriginalUrlMetadata()
    {
        var headers = BaseHeaders(CreateToken(ipk: ValidPublicKey));
        headers[ApproovFunctionRequestBuilder.OriginalUrlHeader] = new[] { "https://api.example.com/token?x=1" };

        var (request, error) = ApproovFunctionRequestBuilder.FromMirroredRequest(headers, Array.Empty<byte>(), 1024);

        Assert.Null(error);
        Assert.Equal("https://api.example.com/token?x=1", request!.TargetUri);
    }

    private static ApproovRequestValidator CreateValidator(IReadOnlyList<string>? bindingHeaders = null, long maxBodyBytes = 10 * 1024 * 1024)
    {
        var options = new ApproovValidationOptions
        {
            ApproovBase64Secret = TestSecretBase64,
            TokenBindingHeaders = bindingHeaders ?? Array.Empty<string>(),
            MessageSigningMode = ApproovMessageSigningMode.Required,
            SignatureMaximumAge = TimeSpan.FromMinutes(10),
            SignatureAllowedClockSkew = TimeSpan.FromMinutes(5),
            MaxBodyBytes = maxBodyBytes
        };

        var verifier = new ApproovMessageSignatureVerifier(
            NullLogger<ApproovMessageSignatureVerifier>.Instance,
            options);

        return new ApproovRequestValidator(
            options,
            verifier,
            NullLogger<ApproovRequestValidator>.Instance);
    }

    private static ApproovSignedRequest BuildSignedRequest(
        string? token,
        params (string Header, string Value)[] extraHeaders)
    {
        return BuildSignedRequest(token, Array.Empty<byte>(), includeContentDigest: false, extraHeaders);
    }

    private static ApproovSignedRequest BuildSignedRequest(
        string? token,
        byte[] body,
        bool includeContentDigest,
        params (string Header, string Value)[] extraHeaders)
    {
        return BuildSignedRequest(token, body, includeContentDigest, signatureInput: null, created: null, expires: null, extraHeaders);
    }

    private static ApproovSignedRequest BuildSignedRequest(
        string? token,
        long? created = null,
        long? expires = null,
        string? signatureInput = null)
    {
        return BuildSignedRequest(token, Array.Empty<byte>(), includeContentDigest: false, signatureInput, created, expires, Array.Empty<(string Header, string Value)>());
    }

    private static ApproovSignedRequest BuildSignedRequest(
        string? token,
        byte[] body,
        bool includeContentDigest,
        string? signatureInput,
        long? created,
        long? expires,
        params (string Header, string Value)[] extraHeaders)
    {
        var headers = BaseHeaders(token, created, expires, signatureInput);
        foreach (var (header, value) in extraHeaders)
        {
            headers[header] = new[] { value };
        }

        if (includeContentDigest)
        {
            headers["Content-Digest"] = new[] { $"sha-256=:{Convert.ToBase64String(SHA256.HashData(body))}:" };
        }

        var unsigned = new ApproovSignedRequest("GET", "https", "api.example.com", "/token", "?param=value", headers, body);
        headers["Signature"] = new[] { $"install=:{SignCanonicalMessage(BuildCanonicalMessage(unsigned))}:" };

        return new ApproovSignedRequest("GET", "https", "api.example.com", "/token", "?param=value", headers, body);
    }

    private static Dictionary<string, IReadOnlyList<string>> BaseHeaders(string? token, long? createdOverride = null, long? expiresOverride = null, string? signatureInputOverride = null)
    {
        var created = createdOverride ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30;
        var expires = expiresOverride ?? created + 600;
        var headers = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            [ApproovFunctionRequestBuilder.OriginalMethodHeader] = new[] { "GET" },
            [ApproovFunctionRequestBuilder.OriginalSchemeHeader] = new[] { "https" },
            [ApproovFunctionRequestBuilder.OriginalHostHeader] = new[] { "api.example.com" },
            [ApproovFunctionRequestBuilder.OriginalPathHeader] = new[] { "/token" },
            [ApproovFunctionRequestBuilder.OriginalQueryHeader] = new[] { "?param=value" },
            ["Signature-Input"] = new[] { signatureInputOverride ?? $"install=(\"@method\" \"@target-uri\" \"approov-token\");alg=\"ecdsa-p256-sha256\";created={created};expires={expires}" }
        };

        if (!string.IsNullOrWhiteSpace(token))
        {
            headers["Approov-Token"] = new[] { token };
        }

        return headers;
    }

    private static string CreateToken(
        DateTime? expires = null,
        string? secretBase64 = null,
        string? pay = null,
        string? ipk = null)
    {
        var secret = Convert.FromBase64String(secretBase64 ?? TestSecretBase64);
        var claims = new List<Claim>
        {
            new("did", "ExampleDevice")
        };

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

    private static string BuildCanonicalMessage(ApproovSignedRequest request)
    {
        var parseError = SfvParser.ParseDictionary(request.GetHeaderValue("Signature-Input"), out var dictionary);
        Assert.False(parseError.HasValue, parseError?.Message ?? "Failed to parse Signature-Input header");
        Assert.NotNull(dictionary);
        Assert.True(dictionary.TryGetValue("install", out var signatureInputItem));

        var components = Assert.IsAssignableFrom<IReadOnlyList<ParsedItem>>(signatureInputItem.Value);
        var lines = new List<string>();

        foreach (var component in components)
        {
            var identifier = Assert.IsType<string>(component.Value);
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
        var messageBytes = Encoding.UTF8.GetBytes(canonicalMessage);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(Convert.FromBase64String(TestPrivateKey), out _);
        return Convert.ToBase64String(ecdsa.SignData(
            messageBytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    private static ApproovSignedRequest WithHeader(ApproovSignedRequest request, string headerName, string headerValue)
    {
        var headers = request.Headers.ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);
        headers[headerName] = new[] { headerValue };
        return new ApproovSignedRequest(request.Method, request.Scheme, request.Host, request.Path, request.Query, headers, request.Body, request.OriginalUrl);
    }
}
