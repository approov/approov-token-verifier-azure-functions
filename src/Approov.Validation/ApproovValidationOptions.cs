namespace Approov.Validation;

public sealed class ApproovValidationOptions
{
    public string? ApproovBase64Secret { get; set; }

    public IReadOnlyList<string> TokenBindingHeaders { get; set; } = Array.Empty<string>();

    public ApproovMessageSigningMode MessageSigningMode { get; set; } = ApproovMessageSigningMode.Required;

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

        return Convert.FromBase64String(ApproovBase64Secret);
    }
}

public enum ApproovMessageSigningMode
{
    Required,
    Optional,
    Disabled
}
