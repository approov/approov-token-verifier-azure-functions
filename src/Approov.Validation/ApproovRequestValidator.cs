namespace Approov.Validation;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

public sealed class ApproovRequestValidator
{
    private readonly ApproovValidationOptions _options;
    private readonly ApproovMessageSignatureVerifier _signatureVerifier;
    private readonly ILogger<ApproovRequestValidator> _logger;

    public ApproovRequestValidator(
        ApproovValidationOptions options,
        ApproovMessageSignatureVerifier signatureVerifier,
        ILogger<ApproovRequestValidator> logger)
    {
        _options = options;
        _signatureVerifier = signatureVerifier;
        _logger = logger;
    }

    public ApproovValidationResult Validate(ApproovSignedRequest request)
    {
        return ValidateRequest(request) with { ClientStatus = ApproovClientStatus.Read(request, _options.StatusHeaderName) };
    }

    private ApproovValidationResult ValidateRequest(ApproovSignedRequest request)
    {
        if (request.Body.LongLength > _options.MaxBodyBytes)
        {
            return ApproovValidationResult.PayloadTooLarge($"Request body exceeds {_options.MaxBodyBytes} bytes.");
        }

        var token = request.GetHeaderValue("Approov-Token");
        if (string.IsNullOrWhiteSpace(token))
        {
            return ApproovValidationResult.Unauthorized("missing_approov_token", "Approov-Token header is missing.");
        }

        var tokenResult = ValidateToken(token);
        if (!tokenResult.Success)
        {
            return ApproovValidationResult.Unauthorized(tokenResult.ReasonCode!, tokenResult.Message!);
        }

        var bindingResult = ValidateTokenBinding(request, tokenResult.PayClaim);
        if (!bindingResult.Success)
        {
            return bindingResult.Result!;
        }

        var signatureResult = ValidateMessageSignature(request, tokenResult.InstallationPublicKey);
        if (!signatureResult.Success)
        {
            return signatureResult.Result!;
        }

        return ApproovValidationResult.Valid(
            tokenResult.DeviceId,
            tokenResult.TokenExpiryUtc,
            bindingResult.Verified,
            signatureResult.Verified);
    }

    private TokenValidationOutcome ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var unvalidatedToken = tokenHandler.ReadJwtToken(token);
            var tokenAlgorithm = unvalidatedToken.Header.Alg;
            if (!_options.TokenSigningAlgorithms.Contains(tokenAlgorithm, StringComparer.Ordinal))
            {
                return TokenValidationOutcome.Failure(
                    "invalid_approov_token_algorithm",
                    $"Approov token signing algorithm '{tokenAlgorithm ?? "<missing>"}' is not configured.");
            }

            var signingKeys = ResolveTokenSigningKeys(tokenAlgorithm).ToArray();
            if (signingKeys.Length == 0)
            {
                throw new InvalidOperationException($"No Approov token signing key is configured for algorithm '{tokenAlgorithm}'.");
            }

            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidAlgorithms = _options.TokenSigningAlgorithms,
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.Zero
            }, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                return TokenValidationOutcome.Failure("invalid_approov_token", "Approov token is not a JWT.");
            }

            var deviceId = jwtToken.Claims.FirstOrDefault(claim => string.Equals(claim.Type, "did", StringComparison.OrdinalIgnoreCase))?.Value;
            var payClaim = jwtToken.Claims.FirstOrDefault(claim => string.Equals(claim.Type, "pay", StringComparison.OrdinalIgnoreCase))?.Value;
            var ipkClaim = jwtToken.Claims.FirstOrDefault(claim => string.Equals(claim.Type, "ipk", StringComparison.OrdinalIgnoreCase))?.Value;

            return TokenValidationOutcome.Valid(jwtToken.ValidTo, deviceId, payClaim, ipkClaim);
        }
        catch (SecurityTokenExpiredException)
        {
            return TokenValidationOutcome.Failure("expired_approov_token", "Approov token is expired.");
        }
        catch (SecurityTokenNoExpirationException)
        {
            return TokenValidationOutcome.Failure("missing_approov_token_expiry", "Approov token is missing exp.");
        }
        catch (SecurityTokenInvalidSignatureException)
        {
            return TokenValidationOutcome.Failure("invalid_approov_token_signature", "Approov token signature is invalid.");
        }
        catch (ArgumentException)
        {
            return TokenValidationOutcome.Failure("invalid_approov_token", "Approov token validation failed.");
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Approov token signing public key is not configured correctly.", ex);
        }
        catch (SecurityTokenException)
        {
            return TokenValidationOutcome.Failure("invalid_approov_token", "Approov token validation failed.");
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected Approov token validation failure.");
            return TokenValidationOutcome.Failure("approov_token_validation_error", "Approov token validation failed unexpectedly.");
        }
    }

    private IEnumerable<SecurityKey> ResolveTokenSigningKeys(string? algorithm)
    {
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            yield break;
        }

        if (IsHmacAlgorithm(algorithm))
        {
            yield return new SymmetricSecurityKey(_options.GetSecretBytes());
            yield break;
        }

        var publicKeyPem = _options.GetPublicKeyPem();
        if (IsRsaAlgorithm(algorithm))
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            yield return new RsaSecurityKey(rsa);
            yield break;
        }

        if (IsEcdsaAlgorithm(algorithm))
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);
            yield return new ECDsaSecurityKey(ecdsa);
        }
    }

    private static bool IsHmacAlgorithm(string algorithm)
    {
        return string.Equals(algorithm, SecurityAlgorithms.HmacSha256, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.HmacSha384, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.HmacSha512, StringComparison.Ordinal);
    }

    private static bool IsRsaAlgorithm(string algorithm)
    {
        return string.Equals(algorithm, SecurityAlgorithms.RsaSha256, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.RsaSha384, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.RsaSha512, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.RsaSsaPssSha256, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.RsaSsaPssSha384, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.RsaSsaPssSha512, StringComparison.Ordinal);
    }

    private static bool IsEcdsaAlgorithm(string algorithm)
    {
        return string.Equals(algorithm, SecurityAlgorithms.EcdsaSha256, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.EcdsaSha384, StringComparison.Ordinal) ||
            string.Equals(algorithm, SecurityAlgorithms.EcdsaSha512, StringComparison.Ordinal);
    }

    private BindingValidationOutcome ValidateTokenBinding(ApproovSignedRequest request, string? payClaim)
    {
        if (_options.TokenBindingHeaders.Count == 0)
        {
            return BindingValidationOutcome.Valid(false);
        }

        if (string.IsNullOrWhiteSpace(payClaim))
        {
            return BindingValidationOutcome.Invalid(ApproovValidationResult.Unauthorized(
                "missing_token_binding_claim",
                "Approov token binding is configured but the pay claim is missing."));
        }

        var bindingValue = new StringBuilder();
        var missingHeaders = new List<string>();

        foreach (var headerName in _options.TokenBindingHeaders)
        {
            var value = request.GetHeaderValue(headerName);
            if (string.IsNullOrWhiteSpace(value))
            {
                missingHeaders.Add(headerName);
                continue;
            }

            bindingValue.Append(value.Trim());
        }

        if (missingHeaders.Count > 0)
        {
            return BindingValidationOutcome.Invalid(ApproovValidationResult.BadRequest(
                "missing_token_binding_header",
                $"Missing token binding header(s): {string.Join(", ", missingHeaders)}."));
        }

        var computedHash = Sha256Base64(bindingValue.ToString());
        if (!FixedTimeEquals(payClaim, computedHash))
        {
            return BindingValidationOutcome.Invalid(ApproovValidationResult.Unauthorized(
                "invalid_token_binding",
                "Approov token binding does not match the configured header values."));
        }

        return BindingValidationOutcome.Valid(true);
    }

    private SignatureValidationOutcome ValidateMessageSignature(ApproovSignedRequest request, string? installationPublicKey)
    {
        if (_options.MessageSigningMode == ApproovMessageSigningMode.Disabled)
        {
            return SignatureValidationOutcome.Valid(false);
        }

        var hasSignature = !string.IsNullOrWhiteSpace(request.GetHeaderValue("Signature"));
        var hasSignatureInput = !string.IsNullOrWhiteSpace(request.GetHeaderValue("Signature-Input"));

        if (!hasSignature && !hasSignatureInput && _options.MessageSigningMode == ApproovMessageSigningMode.Optional)
        {
            return SignatureValidationOutcome.Valid(false);
        }

        if (!hasSignature || !hasSignatureInput)
        {
            return SignatureValidationOutcome.Invalid(ApproovValidationResult.Unauthorized(
                "missing_message_signature",
                "Signature and Signature-Input headers are required."));
        }

        if (string.IsNullOrWhiteSpace(installationPublicKey))
        {
            return SignatureValidationOutcome.Invalid(ApproovValidationResult.Unauthorized(
                "missing_installation_public_key",
                "Approov token is missing the ipk claim required for message signing."));
        }

        var result = _signatureVerifier.Verify(request, installationPublicKey);
        if (!result.Success)
        {
            return SignatureValidationOutcome.Invalid(ApproovValidationResult.Unauthorized(
                "invalid_message_signature",
                result.Error ?? "Approov message signature validation failed."));
        }

        return SignatureValidationOutcome.Valid(true);
    }

    private static string Sha256Base64(string input)
    {
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }

    private static bool FixedTimeEquals(string expected, string actual)
    {
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(actual));
    }

    private sealed record TokenValidationOutcome(
        bool Success,
        string? ReasonCode,
        string? Message,
        DateTime? TokenExpiryUtc,
        string? DeviceId,
        string? PayClaim,
        string? InstallationPublicKey)
    {
        public static TokenValidationOutcome Valid(DateTime tokenExpiryUtc, string? deviceId, string? payClaim, string? installationPublicKey) =>
            new(true, null, null, DateTime.SpecifyKind(tokenExpiryUtc, DateTimeKind.Utc), deviceId, payClaim, installationPublicKey);

        public static TokenValidationOutcome Failure(string reasonCode, string message) =>
            new(false, reasonCode, message, null, null, null, null);
    }

    private sealed record BindingValidationOutcome(bool Success, bool Verified, ApproovValidationResult? Result)
    {
        public static BindingValidationOutcome Valid(bool verified) => new(true, verified, null);

        public static BindingValidationOutcome Invalid(ApproovValidationResult result) => new(false, false, result);
    }

    private sealed record SignatureValidationOutcome(bool Success, bool Verified, ApproovValidationResult? Result)
    {
        public static SignatureValidationOutcome Valid(bool verified) => new(true, verified, null);

        public static SignatureValidationOutcome Invalid(ApproovValidationResult result) => new(false, false, result);
    }
}
