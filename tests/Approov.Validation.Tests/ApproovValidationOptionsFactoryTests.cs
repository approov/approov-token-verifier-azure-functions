namespace Approov.Validation.Tests;

using Approov.Validation;

public sealed class ApproovValidationOptionsFactoryTests
{
    [Fact]
    public void FromEnvironment_WithConfiguredValues_ParsesOptions()
    {
        WithEnvironment(new Dictionary<string, string?>
        {
            ["APPROOV_BASE64_SECRET"] = ApproovRequestValidatorTestData.TestSecretBase64,
            ["APPROOV_TOKEN_BINDING_HEADERS"] = "Authorization, X-Device-Id",
            ["APPROOV_MESSAGE_SIGNING_MODE"] = "optional",
            ["APPROOV_SIGNATURE_REQUIRE_CREATED"] = "false",
            ["APPROOV_SIGNATURE_REQUIRE_EXPIRES"] = "true",
            ["APPROOV_SIGNATURE_MAX_AGE_SECONDS"] = "120",
            ["APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS"] = "15",
            ["APPROOV_MAX_BODY_BYTES"] = "4096"
        }, () =>
        {
            var options = ApproovValidationOptionsFactory.FromEnvironment();

            Assert.Equal(ApproovRequestValidatorTestData.TestSecretBase64, options.ApproovBase64Secret);
            Assert.Equal(new[] { "Authorization", "X-Device-Id" }, options.TokenBindingHeaders);
            Assert.Equal(ApproovMessageSigningMode.Optional, options.MessageSigningMode);
            Assert.False(options.SignatureRequireCreated);
            Assert.True(options.SignatureRequireExpires);
            Assert.Equal(TimeSpan.FromSeconds(120), options.SignatureMaximumAge);
            Assert.Equal(TimeSpan.FromSeconds(15), options.SignatureAllowedClockSkew);
            Assert.Equal(4096, options.MaxBodyBytes);
        });
    }

    [Fact]
    public void FromEnvironment_WithInvalidValues_UsesSafeDefaults()
    {
        WithEnvironment(new Dictionary<string, string?>
        {
            ["APPROOV_BASE64_SECRET"] = null,
            ["APPROOV_TOKEN_BINDING_HEADERS"] = "",
            ["APPROOV_MESSAGE_SIGNING_MODE"] = "invalid",
            ["APPROOV_SIGNATURE_REQUIRE_CREATED"] = "invalid",
            ["APPROOV_SIGNATURE_REQUIRE_EXPIRES"] = "invalid",
            ["APPROOV_SIGNATURE_MAX_AGE_SECONDS"] = "-1",
            ["APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS"] = "invalid",
            ["APPROOV_MAX_BODY_BYTES"] = "-1"
        }, () =>
        {
            var options = ApproovValidationOptionsFactory.FromEnvironment();

            Assert.Null(options.ApproovBase64Secret);
            Assert.Empty(options.TokenBindingHeaders);
            Assert.Equal(ApproovMessageSigningMode.Required, options.MessageSigningMode);
            Assert.True(options.SignatureRequireCreated);
            Assert.False(options.SignatureRequireExpires);
            Assert.Equal(TimeSpan.FromSeconds(300), options.SignatureMaximumAge);
            Assert.Equal(TimeSpan.FromSeconds(60), options.SignatureAllowedClockSkew);
            Assert.Equal(10 * 1024 * 1024, options.MaxBodyBytes);
        });
    }

    private static void WithEnvironment(IReadOnlyDictionary<string, string?> values, Action action)
    {
        var oldValues = values.ToDictionary(entry => entry.Key, entry => Environment.GetEnvironmentVariable(entry.Key));
        try
        {
            foreach (var (key, value) in values)
            {
                Environment.SetEnvironmentVariable(key, value);
            }

            action();
        }
        finally
        {
            foreach (var (key, value) in oldValues)
            {
                Environment.SetEnvironmentVariable(key, value);
            }
        }
    }
}
