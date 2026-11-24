namespace Approov.Validation.Functions;

using System.Net;
using System.Text.Json;
using Approov.Validation;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

public sealed class VerifyApproovFunction
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ApproovValidationOptions _options;
    private readonly ApproovRequestValidator _validator;
    private readonly ILogger<VerifyApproovFunction> _logger;

    public VerifyApproovFunction(
        ApproovValidationOptions options,
        ApproovRequestValidator validator,
        ILogger<VerifyApproovFunction> logger)
    {
        _options = options;
        _validator = validator;
        _logger = logger;
    }

    [Function("VerifyApproov")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "head", "post", "put", "patch", "delete", Route = "approov/verify")]
        HttpRequestData req)
    {
        try
        {
            var headers = req.Headers.ToDictionary(
                header => header.Key,
                header => (IReadOnlyList<string>)header.Value.ToArray(),
                StringComparer.OrdinalIgnoreCase);
            var body = await ReadBodyAsync(req, _options.MaxBodyBytes);
            if (body is null)
            {
                return await WriteResultAsync(req, ApproovValidationResult.PayloadTooLarge($"Request body exceeds {_options.MaxBodyBytes} bytes."));
            }

            var buildResult = ApproovFunctionRequestBuilder.FromMirroredRequest(headers, body, _options.MaxBodyBytes);
            if (buildResult.Error is not null)
            {
                return await WriteResultAsync(req, buildResult.Error);
            }

            var result = _validator.Validate(buildResult.Request!);
            if (!result.IsValid)
            {
                _logger.LogInformation("Approov validation rejected request: {ReasonCode}; client token-fetch status: {ClientStatus}",
                    result.ReasonCode, result.ClientStatus ?? "missing");
            }

            return await WriteResultAsync(req, result);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Approov validation configuration error.");
            return await WriteResultAsync(req, ApproovValidationResult.ServerError(
                "approov_configuration_error",
                "Approov validation is not configured correctly."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected Approov validation error.");
            return await WriteResultAsync(req, ApproovValidationResult.ServerError(
                "approov_validation_error",
                "Approov validation failed unexpectedly."));
        }
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpRequestData req, long maxBodyBytes)
    {
        using var memory = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        long total = 0;

        while ((read = await req.Body.ReadAsync(buffer)) > 0)
        {
            total += read;
            if (total > maxBodyBytes)
            {
                return null;
            }

            memory.Write(buffer, 0, read);
        }

        return memory.ToArray();
    }

    private static async Task<HttpResponseData> WriteResultAsync(HttpRequestData req, ApproovValidationResult result)
    {
        var response = req.CreateResponse((HttpStatusCode)result.StatusCode);
        response.Headers.Add("Content-Type", "application/json; charset=utf-8");

        if (result.IsValid)
        {
            response.Headers.Add("X-Approov-Verified", "true");
            if (!string.IsNullOrWhiteSpace(result.DeviceId))
            {
                response.Headers.Add("X-Approov-Device-Id", result.DeviceId);
            }

            if (result.TokenExpiryUtc.HasValue)
            {
                response.Headers.Add("X-Approov-Token-Expiry", result.TokenExpiryUtc.Value.ToUniversalTime().ToString("O"));
            }
        }

        await response.WriteStringAsync(JsonSerializer.Serialize(new
        {
            valid = result.IsValid,
            reasonCode = result.ReasonCode,
            message = result.Message,
            clientStatus = result.ClientStatus,
            deviceId = result.DeviceId,
            tokenExpiryUtc = result.TokenExpiryUtc,
            tokenBindingVerified = result.TokenBindingVerified,
            messageSignatureVerified = result.MessageSignatureVerified
        }, JsonOptions));

        return response;
    }
}
