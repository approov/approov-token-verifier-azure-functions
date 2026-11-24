namespace Approov.Validation;

public static class ApproovValidationOptionsFactory
{
    private static readonly string[] DefaultHmacAlgorithms =
    {
        "HS256"
    };

    public static ApproovValidationOptions FromEnvironment()
    {
        var publicKeyPem = Environment.GetEnvironmentVariable("APPROOV_PUBLIC_KEY_PEM");
        var publicKeyBase64 = Environment.GetEnvironmentVariable("APPROOV_PUBLIC_KEY_BASE64");
        var statusHeader = Environment.GetEnvironmentVariable("APPROOV_STATUS_HEADER_NAME");

        return new ApproovValidationOptions
        {
            ApproovBase64Secret = Environment.GetEnvironmentVariable("APPROOV_BASE64_SECRET"),
            StatusHeaderName = string.IsNullOrWhiteSpace(statusHeader) ? "Approov-Status" : statusHeader.Trim(),
            ApproovPublicKeyPem = publicKeyPem,
            ApproovPublicKeyBase64 = publicKeyBase64,
            TokenSigningAlgorithms = ParseTokenSigningAlgorithms(
                Environment.GetEnvironmentVariable("APPROOV_TOKEN_SIGNING_ALGORITHMS"),
                string.IsNullOrWhiteSpace(publicKeyPem) && string.IsNullOrWhiteSpace(publicKeyBase64)),
            TokenBindingHeaders = ParseHeaderList(Environment.GetEnvironmentVariable("APPROOV_TOKEN_BINDING_HEADERS")),
            MessageSigningMode = ParseMessageSigningMode(Environment.GetEnvironmentVariable("APPROOV_MESSAGE_SIGNING_MODE")),
            RequireSignedContentDigest = ParseBoolean(Environment.GetEnvironmentVariable("APPROOV_REQUIRE_SIGNED_CONTENT_DIGEST"), false),
            SignatureRequireCreated = ParseBoolean(Environment.GetEnvironmentVariable("APPROOV_SIGNATURE_REQUIRE_CREATED"), true),
            SignatureRequireExpires = ParseBoolean(Environment.GetEnvironmentVariable("APPROOV_SIGNATURE_REQUIRE_EXPIRES"), false),
            SignatureMaximumAge = ParseOptionalSeconds(Environment.GetEnvironmentVariable("APPROOV_SIGNATURE_MAX_AGE_SECONDS"), TimeSpan.FromSeconds(300)),
            SignatureAllowedClockSkew = ParseOptionalSeconds(Environment.GetEnvironmentVariable("APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS"), TimeSpan.FromSeconds(60)) ?? TimeSpan.FromSeconds(60),
            MaxBodyBytes = ParseLong(Environment.GetEnvironmentVariable("APPROOV_MAX_BODY_BYTES"), 10 * 1024 * 1024)
        };
    }

    private static IReadOnlyList<string> ParseHeaderList(string? raw)
    {
        return string.IsNullOrWhiteSpace(raw)
            ? Array.Empty<string>()
            : raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(value => value.Length > 0)
                .ToArray();
    }

    private static IReadOnlyList<string> ParseTokenSigningAlgorithms(string? raw, bool defaultToHmac)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return defaultToHmac ? DefaultHmacAlgorithms : Array.Empty<string>();
        }

        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(value => value.Length > 0)
            .Select(value => value.ToUpperInvariant())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static ApproovMessageSigningMode ParseMessageSigningMode(string? raw)
    {
        return Enum.TryParse<ApproovMessageSigningMode>(raw, ignoreCase: true, out var mode)
            ? mode
            : ApproovMessageSigningMode.Required;
    }

    private static bool ParseBoolean(string? raw, bool defaultValue)
    {
        return bool.TryParse(raw, out var value) ? value : defaultValue;
    }

    private static TimeSpan? ParseOptionalSeconds(string? raw, TimeSpan? defaultValue)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return defaultValue;
        }

        return double.TryParse(raw, out var seconds) && seconds >= 0
            ? TimeSpan.FromSeconds(seconds)
            : defaultValue;
    }

    private static long ParseLong(string? raw, long defaultValue)
    {
        return long.TryParse(raw, out var value) && value >= 0 ? value : defaultValue;
    }
}
