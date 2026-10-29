namespace Approov.Validation;

public sealed class ApproovValidationOptions
{
    private static readonly string[] DefaultTokenSigningAlgorithms =
    {
        "HS256"
    };

    public string? ApproovBase64Secret { get; set; }

    public string StatusHeaderName { get; set; } = "Approov-Status";

    public string? ApproovPublicKeyPem { get; set; }

    public string? ApproovPublicKeyBase64 { get; set; }

    public IReadOnlyList<string> TokenSigningAlgorithms { get; set; } = DefaultTokenSigningAlgorithms;

    public IReadOnlyList<string> TokenBindingHeaders { get; set; } = Array.Empty<string>();

    public ApproovMessageSigningMode MessageSigningMode { get; set; } = ApproovMessageSigningMode.Required;

    public bool RequireSignedContentDigest { get; set; } = false;

    public bool SignatureRequireCreated { get; set; } = true;

    public bool SignatureRequireExpires { get; set; } = false;

    public TimeSpan? SignatureMaximumAge { get; set; } = TimeSpan.FromSeconds(300);

    public TimeSpan SignatureAllowedClockSkew { get; set; } = TimeSpan.FromSeconds(60);

    public long MaxBodyBytes { get; set; } = 10 * 1024 * 1024;

    public byte[] GetSecretBytes()
    {
        if (string.IsNullOrWhiteSpace(ApproovBase64Secret))
        {
            throw new InvalidOperationException("APPROOV_BASE64_SECRET is not configured.");
        }

        try
        {
            return Convert.FromBase64String(ApproovBase64Secret);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("APPROOV_BASE64_SECRET is not valid base64.", ex);
        }
    }

    public string GetPublicKeyPem()
    {
        if (!string.IsNullOrWhiteSpace(ApproovPublicKeyPem))
        {
            return ApproovPublicKeyPem.Replace("\\n", Environment.NewLine, StringComparison.Ordinal);
        }

        if (!string.IsNullOrWhiteSpace(ApproovPublicKeyBase64))
        {
            try
            {
                var bytes = Convert.FromBase64String(ApproovPublicKeyBase64);
                var body = Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks);
                return $"-----BEGIN PUBLIC KEY-----{Environment.NewLine}{body}{Environment.NewLine}-----END PUBLIC KEY-----";
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("APPROOV_PUBLIC_KEY_BASE64 is not valid base64.", ex);
            }
        }

        throw new InvalidOperationException("An Approov public key is required for asymmetric token verification.");
    }
}

public enum ApproovMessageSigningMode
{
    Required,
    Optional,
    Disabled
}
