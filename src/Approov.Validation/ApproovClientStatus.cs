namespace Approov.Validation;

// Client diagnostics are not attestation evidence. Never report arbitrary header data.
internal static class ApproovClientStatus
{
    private static readonly HashSet<string> Statuses = new(StringComparer.Ordinal)
    {
        "success", "no_network", "poor_network", "mitm_detected", "untrusted_network",
        "no_approov_service", "bad_url", "unknown_url", "unprotected_url",
        "not_initialized", "rejected", "disabled", "unknown_key", "bad_key",
        "bad_payload", "internal_error"
    };

    public static string? Read(ApproovSignedRequest request, string headerName)
    {
        var values = request.GetHeaderValues(headerName);
        if (values.Count == 0) return null;
        if (values.Count != 1 || values[0].Length > 32) return "invalid";
        var status = values[0].Trim();
        return Statuses.Contains(status) ? status : "invalid";
    }
}
