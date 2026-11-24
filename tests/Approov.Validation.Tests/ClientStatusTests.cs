namespace Approov.Validation.Tests;

using System.Net;
using System.Text.Json;
using Approov.Validation;
using Approov.Validation.Functions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

public sealed class ClientStatusTests
{
    [Theory]
    [InlineData("NO_NETWORK")]
    [InlineData("POOR_NETWORK")]
    [InlineData("MITM_DETECTED")]
    [InlineData("NO_NETWORK_PERMISSION")]
    [InlineData("NOT_INITIALIZED")]
    [InlineData("REJECTED")]
    [InlineData("SUCCESS")]
    public async Task MissingToken_ReportsSdkStatusButStillRejects(string status)
    {
        var (function, logger) = CreateFunction();
        var request = CreateRequest(status);

        var response = await function.Run(request);
        using var body = JsonDocument.Parse(((TestHttpResponseData)response).ReadBody());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("missing_approov_token", body.RootElement.GetProperty("reasonCode").GetString());
        Assert.Equal(status, body.RootElement.GetProperty("clientStatus").GetString());
        Assert.False(response.Headers.TryGetValues("X-Approov-Verified", out _));
        Assert.Contains(logger.Messages, message => message.Contains(status, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "invalid")]
    [InlineData("success", "invalid")]
    [InlineData("no_network", "invalid")]
    [InlineData("UNTRUSTED_NETWORK", "invalid")]
    [InlineData("NO_NETWORK, SUCCESS", "invalid")]
    [InlineData("PRIVATE-HEADER", "invalid")]
    [InlineData("NO_NETWORK\tPRIVATE-HEADER", "invalid")]
    public async Task UntrustedStatus_IsFilteredBeforeReporting(string? status, string? expected)
    {
        var (function, logger) = CreateFunction();
        var response = await function.Run(CreateRequest(status));
        var text = ((TestHttpResponseData)response).ReadBody();
        using var body = JsonDocument.Parse(text);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(expected, body.RootElement.GetProperty("clientStatus").GetString());
        Assert.DoesNotContain("PRIVATE-HEADER", text, StringComparison.Ordinal);
        Assert.DoesNotContain(logger.Messages, message => message.Contains("PRIVATE-HEADER", StringComparison.Ordinal));
    }

    [Fact]
    public async Task EmptyToken_WithReportedSuccess_IsStillRejected()
    {
        var request = CreateRequest("SUCCESS");
        request.Headers.Add("Approov-Token", "");
        var response = await CreateFunction().Function.Run(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("missing_approov_token", ((TestHttpResponseData)response).ReadBody(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DuplicateOrOversizedStatus_IsNotReportedVerbatim(bool oversized)
    {
        var request = CreateRequest(oversized ? new string('x', 10000) : "NO_NETWORK");
        if (!oversized) request.Headers.Add("Approov-Status", "SUCCESS");
        var response = await CreateFunction().Function.Run(request);
        using var body = JsonDocument.Parse(((TestHttpResponseData)response).ReadBody());
        Assert.Equal("invalid", body.RootElement.GetProperty("clientStatus").GetString());
    }

    [Fact]
    public async Task CustomHeader_ReportsStatusWithoutChangingTokenValidation()
    {
        var token = ApproovRequestValidatorTestData.CreateToken(ipk: ApproovRequestValidatorTestData.ValidPublicKey);
        var signed = ApproovRequestValidatorTestData.BuildSignedRequest(token);
        var headers = signed.Headers.ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);
        headers["x-client-status"] = new[] { "NO_NETWORK" };
        headers["Approov-Status"] = new[] { "SUCCESS" };
        var response = await CreateFunction("X-Client-Status").Function.Run(new TestHttpRequestData(headers, signed.Body));
        using var body = JsonDocument.Parse(((TestHttpResponseData)response).ReadBody());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("NO_NETWORK", body.RootElement.GetProperty("clientStatus").GetString());
    }

    [Fact]
    public void ValidationResult_KeepsPositionalSignature()
    {
        var result = new ApproovValidationResult(false, 401, "missing_approov_token", "Missing token.") { ClientStatus = "NO_NETWORK" };
        var (isValid, statusCode, reasonCode, message, deviceId, tokenExpiryUtc, tokenBindingVerified, messageSignatureVerified) = result;

        Assert.False(isValid);
        Assert.Equal(401, statusCode);
        Assert.Equal("missing_approov_token", reasonCode);
        Assert.Equal("Missing token.", message);
        Assert.Null(deviceId);
        Assert.Null(tokenExpiryUtc);
        Assert.False(tokenBindingVerified);
        Assert.False(messageSignatureVerified);
        Assert.Equal("NO_NETWORK", result.ClientStatus);
    }

    private static TestHttpRequestData CreateRequest(string? status)
    {
        var request = ApproovRequestValidatorTestData.BuildSignedRequest(token: null);
        var headers = request.Headers.ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);
        if (status is not null) headers["Approov-Status"] = new[] { status };
        return new TestHttpRequestData(headers, request.Body);
    }

    private static (VerifyApproovFunction Function, RecordingLogger Logger) CreateFunction(string statusHeaderName = "Approov-Status")
    {
        var options = new ApproovValidationOptions
        {
            ApproovBase64Secret = ApproovRequestValidatorTestData.TestSecretBase64,
            StatusHeaderName = statusHeaderName
        };
        var verifier = new ApproovMessageSignatureVerifier(NullLogger<ApproovMessageSignatureVerifier>.Instance, options);
        var validator = new ApproovRequestValidator(options, verifier, NullLogger<ApproovRequestValidator>.Instance);
        var logger = new RecordingLogger();
        return (new VerifyApproovFunction(options, validator, logger), logger);
    }

    private sealed class RecordingLogger : ILogger<VerifyApproovFunction>
    {
        public List<string> Messages { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }
}
