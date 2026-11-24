namespace Approov.Validation.Tests;

using Approov.Validation;
using Microsoft.Extensions.Logging.Abstractions;

public sealed class DualSignatureTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ValidInstall_WithAccountMember_PassesForEitherOrderOrHeaderLayout(bool accountFirst, bool splitHeaders)
    {
        var request = BuildRequest(accountFirst, splitHeaders);

        var result = CreateValidator().Validate(request);

        Assert.True(result.IsValid);
        Assert.True(result.MessageSignatureVerified);
    }

    [Fact]
    public void ValidInstall_DoesNotRequireAccountVerification()
    {
        var request = BuildRequest();
        var headers = CopyHeaders(request);
        headers["Signature"] = new[] { headers["Signature"][0].Split(", ")[0] + ", account=:AAAA:" };

        var result = CreateValidator().Validate(WithHeaders(request, headers));

        Assert.True(result.IsValid);
        Assert.True(result.MessageSignatureVerified);
    }

    [Fact]
    public void InvalidInstall_CannotBeReplacedByTheAccountMember()
    {
        var request = BuildRequest();
        var headers = CopyHeaders(request);
        headers["Signature"] = new[] { "install=:AAAA:, " + headers["Signature"][0].Split(", ")[1] };

        var result = CreateValidator().Validate(WithHeaders(request, headers));

        Assert.False(result.IsValid);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Theory]
    [InlineData("Signature")]
    [InlineData("Signature-Input")]
    public void MismatchedMemberLabels_AreRejected(string headerName)
    {
        var request = BuildRequest();
        var headers = CopyHeaders(request);
        headers[headerName] = new[] { headers[headerName][0].Split(", ")[0] };

        var result = CreateValidator().Validate(WithHeaders(request, headers));

        Assert.False(result.IsValid);
        Assert.Equal("invalid_message_signature", result.ReasonCode);
    }

    [Fact]
    public void AccountOnly_DoesNotBypassTheInstallRequirement()
    {
        var request = BuildRequest();
        var headers = CopyHeaders(request);
        foreach (var name in new[] { "Signature", "Signature-Input" })
            headers[name] = new[] { headers[name][0].Split(", ")[1] };

        Assert.False(CreateValidator().Validate(WithHeaders(request, headers)).IsValid);
    }

    private static ApproovSignedRequest BuildRequest(bool accountFirst = false, bool splitHeaders = false)
    {
        var token = ApproovRequestValidatorTestData.CreateToken(ipk: ApproovRequestValidatorTestData.ValidPublicKey, mskid: "test-account-key");
        var request = ApproovRequestValidatorTestData.BuildSignedRequest(token, includeAccountSignature: true);
        var headers = CopyHeaders(request);
        foreach (var name in new[] { "Signature", "Signature-Input" })
        {
            var entries = headers[name][0].Split(", ");
            if (accountFirst) Array.Reverse(entries);
            headers[name] = splitHeaders ? entries : new[] { string.Join(", ", entries) };
        }
        return WithHeaders(request, headers);
    }

    private static Dictionary<string, IReadOnlyList<string>> CopyHeaders(ApproovSignedRequest request) =>
        request.Headers.ToDictionary(entry => entry.Key, entry => entry.Value, StringComparer.OrdinalIgnoreCase);

    private static ApproovSignedRequest WithHeaders(ApproovSignedRequest request, IReadOnlyDictionary<string, IReadOnlyList<string>> headers) =>
        new(request.Method, request.Scheme, request.Host, request.Path, request.Query, headers, request.Body);

    private static ApproovRequestValidator CreateValidator()
    {
        var options = new ApproovValidationOptions { ApproovBase64Secret = ApproovRequestValidatorTestData.TestSecretBase64 };
        return new ApproovRequestValidator(options,
            new ApproovMessageSignatureVerifier(NullLogger<ApproovMessageSignatureVerifier>.Instance, options),
            NullLogger<ApproovRequestValidator>.Instance);
    }
}
