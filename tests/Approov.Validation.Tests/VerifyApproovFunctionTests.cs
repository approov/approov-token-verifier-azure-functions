namespace Approov.Validation.Tests;

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Approov.Validation;
using Approov.Validation.Functions;
using Microsoft.Extensions.Logging.Abstractions;

public sealed class VerifyApproovFunctionTests
{
    [Fact]
    public async Task Run_WithValidMirroredRequest_ReturnsOkAndTrustedHeaders()
    {
        var token = ApproovRequestValidatorTestData.CreateToken(ipk: ApproovRequestValidatorTestData.ValidPublicKey);
        var request = ApproovRequestValidatorTestData.BuildSignedRequest(token);
        var functionRequest = new TestHttpRequestData(request.Headers, request.Body);

        var response = await CreateFunction().Run(functionRequest);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("true", response.Headers.GetValues("X-Approov-Verified").Single());
        Assert.Equal("ExampleDevice", response.Headers.GetValues("X-Approov-Device-Id").Single());
        Assert.DoesNotContain(token, ((TestHttpResponseData)response).ReadBody(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Run_WithInvalidRequest_ReturnsUnauthorizedJsonWithoutSensitiveHeaders()
    {
        var request = ApproovRequestValidatorTestData.BuildSignedRequest(token: null);
        var response = await CreateFunction().Run(new TestHttpRequestData(request.Headers, request.Body));
        var body = ((TestHttpResponseData)response).ReadBody();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("\"valid\":false", body, StringComparison.Ordinal);
        Assert.Contains("missing_approov_token", body, StringComparison.Ordinal);
        Assert.False(response.Headers.TryGetValues("X-Approov-Verified", out _));
    }

    [Fact]
    public async Task Run_WithMissingApimMetadata_ReturnsBadRequest()
    {
        var response = await CreateFunction().Run(new TestHttpRequestData(
            new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase),
            Array.Empty<byte>()));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("missing_original_request_metadata", ((TestHttpResponseData)response).ReadBody(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Run_WithOversizedBody_ReturnsPayloadTooLarge()
    {
        var token = ApproovRequestValidatorTestData.CreateToken(ipk: ApproovRequestValidatorTestData.ValidPublicKey);
        var request = ApproovRequestValidatorTestData.BuildSignedRequest(token, body: new byte[8], includeContentDigest: false);
        var response = await CreateFunction(maxBodyBytes: 4).Run(new TestHttpRequestData(request.Headers, request.Body));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Contains("request_body_too_large", ((TestHttpResponseData)response).ReadBody(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Run_WithConfigurationError_ReturnsServerError()
    {
        var token = ApproovRequestValidatorTestData.CreateToken(ipk: ApproovRequestValidatorTestData.ValidPublicKey);
        var request = ApproovRequestValidatorTestData.BuildSignedRequest(token);
        var response = await CreateFunction(secretBase64: null).Run(new TestHttpRequestData(request.Headers, request.Body));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains("approov_configuration_error", ((TestHttpResponseData)response).ReadBody(), StringComparison.Ordinal);
    }

    private static VerifyApproovFunction CreateFunction(long maxBodyBytes = 10 * 1024 * 1024, string? secretBase64 = ApproovRequestValidatorTestData.TestSecretBase64)
    {
        var options = new ApproovValidationOptions
        {
            ApproovBase64Secret = secretBase64,
            MaxBodyBytes = maxBodyBytes,
            SignatureMaximumAge = TimeSpan.FromMinutes(10),
            SignatureAllowedClockSkew = TimeSpan.FromMinutes(5)
        };
        var verifier = new ApproovMessageSignatureVerifier(NullLogger<ApproovMessageSignatureVerifier>.Instance, options);
        var validator = new ApproovRequestValidator(options, verifier, NullLogger<ApproovRequestValidator>.Instance);
        return new VerifyApproovFunction(options, validator, NullLogger<VerifyApproovFunction>.Instance);
    }
}
