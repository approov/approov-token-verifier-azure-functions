namespace Approov.Validation;

// Client diagnostics are not attestation evidence. Never report arbitrary header data.
internal static class ApproovClientStatus
{
    // SDK token fetch status names, sent unchanged by 3.7.0 service layers.
    // NO_NETWORK_PERMISSION and MISSING_LIB_DEPENDENCY are Android only; NOT_INITIALIZED is iOS only.
    private static readonly HashSet<string> Statuses = new(StringComparer.Ordinal)
    {
        "SUCCESS", "NO_NETWORK", "POOR_NETWORK", "MITM_DETECTED", "NO_APPROOV_SERVICE",
        "BAD_URL", "UNKNOWN_URL", "UNPROTECTED_URL", "NO_NETWORK_PERMISSION",
        "MISSING_LIB_DEPENDENCY", "NOT_INITIALIZED", "REJECTED", "DISABLED",
        "UNKNOWN_KEY", "BAD_KEY", "BAD_PAYLOAD", "INTERNAL_ERROR"
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
