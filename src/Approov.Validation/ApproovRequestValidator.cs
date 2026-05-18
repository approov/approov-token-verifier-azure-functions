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
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_options.GetSecretBytes()),
                ValidateIssuer = false,
                ValidateAudience = false,
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
