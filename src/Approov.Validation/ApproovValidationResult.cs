namespace Approov.Validation;

public sealed record ApproovValidationResult(
    bool IsValid,
    int StatusCode,
    string ReasonCode,
    string Message,
    string? DeviceId = null,
    DateTime? TokenExpiryUtc = null,
    bool TokenBindingVerified = false,
    bool MessageSignatureVerified = false,
    string? ClientStatus = null)
{
    public static ApproovValidationResult Valid(
        string? deviceId,
        DateTime? tokenExpiryUtc,
        bool tokenBindingVerified,
        bool messageSignatureVerified) =>
        new(true, 200, "approov_valid", "Approov validation succeeded.", deviceId, tokenExpiryUtc, tokenBindingVerified, messageSignatureVerified);

    public static ApproovValidationResult BadRequest(string reasonCode, string message) =>
        new(false, 400, reasonCode, message);

    public static ApproovValidationResult Unauthorized(string reasonCode, string message) =>
        new(false, 401, reasonCode, message);

    public static ApproovValidationResult PayloadTooLarge(string message) =>
        new(false, 413, "request_body_too_large", message);

    public static ApproovValidationResult ServerError(string reasonCode, string message) =>
        new(false, 500, reasonCode, message);
}
