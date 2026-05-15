namespace Approov.Validation;

public static class ApproovFunctionRequestBuilder
{
    public const string OriginalMethodHeader = "X-Approov-Original-Method";
    public const string OriginalSchemeHeader = "X-Approov-Original-Scheme";
    public const string OriginalHostHeader = "X-Approov-Original-Host";
    public const string OriginalPathHeader = "X-Approov-Original-Path";
    public const string OriginalQueryHeader = "X-Approov-Original-Query";
    public const string OriginalUrlHeader = "X-Approov-Original-Url";

    private static readonly string[] RequiredNonEmptyMetadataHeaders =
    {
        OriginalMethodHeader,
        OriginalSchemeHeader,
        OriginalHostHeader,
        OriginalPathHeader
    };

    public static (ApproovSignedRequest? Request, ApproovValidationResult? Error) FromMirroredRequest(
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        byte[] body,
        long maxBodyBytes)
    {
        foreach (var header in RequiredNonEmptyMetadataHeaders)
        {
            if (string.IsNullOrWhiteSpace(GetHeaderValue(headers, header)))
            {
                return (null, ApproovValidationResult.BadRequest(
                    "missing_original_request_metadata",
                    $"Missing required APIM metadata header: {header}."));
            }
        }

        if (!headers.ContainsKey(OriginalQueryHeader))
        {
            return (null, ApproovValidationResult.BadRequest(
                "missing_original_request_metadata",
                $"Missing required APIM metadata header: {OriginalQueryHeader}."));
        }

        if (body.LongLength > maxBodyBytes)
        {
            return (null, ApproovValidationResult.PayloadTooLarge($"Request body exceeds {maxBodyBytes} bytes."));
        }

        return (new ApproovSignedRequest(
            method: GetHeaderValue(headers, OriginalMethodHeader),
            scheme: GetHeaderValue(headers, OriginalSchemeHeader),
            host: GetHeaderValue(headers, OriginalHostHeader),
            path: GetHeaderValue(headers, OriginalPathHeader),
            query: GetHeaderValue(headers, OriginalQueryHeader),
            headers: headers,
            body: body,
            originalUrl: GetHeaderValue(headers, OriginalUrlHeader)), null);
    }

    private static string GetHeaderValue(IReadOnlyDictionary<string, IReadOnlyList<string>> headers, string name)
    {
        return headers.TryGetValue(name, out var values)
            ? StructuredFieldFormatter.CombineHeaderValues(values)
            : string.Empty;
    }
}
