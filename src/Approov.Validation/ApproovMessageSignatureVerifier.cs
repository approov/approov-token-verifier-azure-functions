namespace Approov.Validation;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using StructuredFieldValues;

// Reconstructs the HTTP message signature base and validates ECDSA P-256 signatures from the Approov SDK.
public sealed class ApproovMessageSignatureVerifier
{
    private static readonly ISet<string> SupportedContentDigestAlgorithms = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "sha-256",
        "sha-512"
    };

    // Collates the structured field parameters that ride alongside the signature input list.
    private sealed record SignatureMetadata(
        string? Algorithm,
        long? Created,
        long? Expires,
        string? KeyId,
        string? Nonce,
        string? Tag);

    private readonly ILogger<ApproovMessageSignatureVerifier> _logger;
    private readonly ApproovValidationOptions _validationOptions;

    public ApproovMessageSignatureVerifier(
        ILogger<ApproovMessageSignatureVerifier> logger,
        ApproovValidationOptions validationOptions)
    {
        _logger = logger;
        _validationOptions = validationOptions;
    }

    // Entry point used by middleware to validate signatures referenced by the 'install' label.
    public MessageSignatureResult Verify(ApproovSignedRequest request, string publicKeyBase64)
    {
        // Signature metadata is supplied via Structured Field headers that may be split across multiple header lines.
        var signatureHeader = StructuredFieldFormatter.CombineHeaderValues(request.GetHeaderValues("Signature"));
        var signatureInputHeader = StructuredFieldFormatter.CombineHeaderValues(request.GetHeaderValues("Signature-Input"));

        _logger.LogDebug(
            "Approov message signing: received Signature length {SignatureLength} and Signature-Input length {SignatureInputLength}",
            signatureHeader.Length,
            signatureInputHeader.Length);

        if (string.IsNullOrWhiteSpace(signatureHeader) || string.IsNullOrWhiteSpace(signatureInputHeader))
        {
            return MessageSignatureResult.Failure("Missing Signature or Signature-Input headers");
        }

        var signatureParseError = SfvParser.ParseDictionary(signatureHeader, out var signatureDictionary);
        if (signatureParseError.HasValue || signatureDictionary is null)
        {
            return MessageSignatureResult.Failure($"Failed to parse signature header: {signatureParseError?.Message ?? "Unknown error"}");
        }

        var signatureInputParseError = SfvParser.ParseDictionary(signatureInputHeader, out var signatureInputDictionary);
        if (signatureInputParseError.HasValue || signatureInputDictionary is null)
        {
            return MessageSignatureResult.Failure($"Failed to parse signature-input header: {signatureInputParseError?.Message ?? "Unknown error"}");
        }

        var headerConsistency = EnsureMatchingSignatureLabels(signatureDictionary, signatureInputDictionary);
        if (!headerConsistency.Success)
        {
            return MessageSignatureResult.Failure(headerConsistency.Error!);
        }

        if (!signatureDictionary.TryGetValue("install", out var signatureItem))
        {
            return MessageSignatureResult.Failure("Signature header missing 'install' entry");
        }

        if (!signatureInputDictionary.TryGetValue("install", out var signatureInputItem))
        {
            return MessageSignatureResult.Failure("Signature-Input header missing 'install' entry");
        }

        if (signatureItem.Value is not ReadOnlyMemory<byte> signatureBytes)
        {
            return MessageSignatureResult.Failure("Signature item is not encoded as a byte sequence");
        }

        if (signatureInputItem.Value is not IReadOnlyList<ParsedItem> componentIdentifiers)
        {
            return MessageSignatureResult.Failure("Signature-Input entry does not contain an inner list of components");
        }

        // Parse and validate signature parameters such as algorithm, created and expires.
        var metadataResult = TryExtractSignatureMetadata(signatureInputItem.Parameters);
        if (!metadataResult.Success)
        {
            return MessageSignatureResult.Failure(metadataResult.Error!);
        }

        var metadata = metadataResult.Metadata!;
        _logger.LogDebug(
            "Approov message signing: metadata alg={Alg} created={Created} expires={Expires} keyId={KeyId} nonce={Nonce} tag={Tag}",
            metadata.Algorithm,
            metadata.Created,
            metadata.Expires,
            metadata.KeyId,
            metadata.Nonce,
            metadata.Tag);
        if (!string.Equals(metadata.Algorithm, "ecdsa-p256-sha256", StringComparison.OrdinalIgnoreCase))
        {
            return MessageSignatureResult.Failure($"Unsupported signature algorithm '{metadata.Algorithm ?? "<missing>"}'");
        }

        // Check the created/expires timestamps according to the configured policy.
        var timestampValidation = ValidateTimestampPolicy(metadata);
        if (!timestampValidation.Success)
        {
            return MessageSignatureResult.Failure(timestampValidation.Error!);
        }

        var canonicalBase = BuildCanonicalMessage(request, componentIdentifiers, signatureInputItem.Parameters);
        if (!canonicalBase.Success)
        {
            return MessageSignatureResult.Failure(canonicalBase.Error!);
        }

        var canonicalPayloadBytes = Encoding.UTF8.GetBytes(canonicalBase.Payload!);
        _logger.LogTrace("Approov message signing: canonical payload length {Length}", canonicalPayloadBytes.Length);

        if (_validationOptions.RequireSignedContentDigest &&
            !string.IsNullOrWhiteSpace(request.GetHeaderValue("Content-Digest")) &&
            !IsComponentCovered(componentIdentifiers, "content-digest"))
        {
            return MessageSignatureResult.Failure("Content-Digest header must be covered by the message signature");
        }

        var contentDigestValidation = VerifyContentDigest(request);
        if (!contentDigestValidation.Success)
        {
            return MessageSignatureResult.Failure(contentDigestValidation.Error!);
        }

        if (!TryVerifySignature(publicKeyBase64, signatureBytes, canonicalPayloadBytes))
        {
            return MessageSignatureResult.Failure("Signature verification failed");
        }

        return MessageSignatureResult.Succeeded(canonicalBase.Payload ?? string.Empty);
    }

    private static (bool Success, string? Error) EnsureMatchingSignatureLabels(
        IReadOnlyDictionary<string, ParsedItem> signatureDictionary,
        IReadOnlyDictionary<string, ParsedItem> signatureInputDictionary)
    {
        var signatureKeys = new HashSet<string>(signatureDictionary.Keys, StringComparer.Ordinal);
        var inputKeys = new HashSet<string>(signatureInputDictionary.Keys, StringComparer.Ordinal);

        // Both headers must expose the same set of labels so that the client cannot inject
        // components or signatures that we never evaluate.
        var missingInInput = signatureKeys.Except(inputKeys).FirstOrDefault();
        if (!string.IsNullOrEmpty(missingInInput))
        {
            return (false, $"Signature-Input header missing '{missingInInput}' entry");
        }

        var missingInSignature = inputKeys.Except(signatureKeys).FirstOrDefault();
        if (!string.IsNullOrEmpty(missingInSignature))
        {
            return (false, $"Signature header missing '{missingInSignature}' entry");
        }

        return (true, null);
    }

    private (bool Success, SignatureMetadata? Metadata, string? Error) TryExtractSignatureMetadata(IReadOnlyDictionary<string, object>? parameters)
    {
        if (parameters is null || parameters.Count == 0)
        {
            return (false, null, "Signature parameters missing 'alg' entry");
        }

        // Rejects unknown parameter keys to tighten the validation 
        string? algorithm = null;
        long? created = null;
        long? expires = null;
        string? keyId = null;
        string? nonce = null;
        string? tag = null;

        foreach (var parameter in parameters)
        {
            switch (parameter.Key)
            {
                case "alg":
                    if (parameter.Value is string text)
                    {
                        algorithm = text;
                    }
                    else
                    {
                        return (false, null, "Signature parameter 'alg' must be a string");
                    }

                    break;
                case "created":
                    if (!TryConvertToLong(parameter.Value, out var createdValue))
                    {
                        return (false, null, "Signature parameter 'created' must be an integer");
                    }

                    created = createdValue;
                    break;
                case "expires":
                    if (!TryConvertToLong(parameter.Value, out var expiresValue))
                    {
                        return (false, null, "Signature parameter 'expires' must be an integer");
                    }

                    expires = expiresValue;
                    break;
                case "keyid":
                    if (parameter.Value is string keyIdValue)
                    {
                        keyId = keyIdValue;
                        break;
                    }

                    return (false, null, "Signature parameter 'keyid' must be a string");
                case "nonce":
                    if (parameter.Value is string nonceValue)
                    {
                        nonce = nonceValue;
                        break;
                    }

                    return (false, null, "Signature parameter 'nonce' must be a string");
                case "tag":
                    if (parameter.Value is string tagValue)
                    {
                        tag = tagValue;
                        break;
                    }

                    return (false, null, "Signature parameter 'tag' must be a string");
                default:
                    return (false, null, $"Unsupported signature parameter '{parameter.Key}'");
            }
        }

        if (string.IsNullOrWhiteSpace(algorithm))
        {
            return (false, null, "Signature missing 'alg' parameter");
        }

        return (true, new SignatureMetadata(algorithm, created, expires, keyId, nonce, tag), null);
    }

    private (bool Success, string? Error) ValidateTimestampPolicy(SignatureMetadata metadata)
    {
        var now = DateTimeOffset.UtcNow;

        if (_validationOptions.SignatureRequireCreated && !metadata.Created.HasValue)
        {
            _logger.LogDebug("Approov message signing: missing created timestamp");
            return (false, "Signature missing 'created' parameter");
        }

        if (metadata.Created.HasValue)
        {
            // Apply both freshness checks and future drift tolerance to the created timestamp.
            var createdInstant = DateTimeOffset.FromUnixTimeSeconds(metadata.Created.Value);
            var freshnessWindow = _validationOptions.SignatureMaximumAge;
            var skew = _validationOptions.SignatureAllowedClockSkew;

            if (freshnessWindow.HasValue && createdInstant < now - freshnessWindow.Value - skew)
            {
                _logger.LogDebug("Approov message signing: created timestamp {Created} is stale compared to window {Window}s", createdInstant.ToUnixTimeSeconds(), freshnessWindow.Value.TotalSeconds);
                return (false, "Signature 'created' timestamp is older than the allowed freshness window");
            }

            if (createdInstant > now + skew)
            {
                _logger.LogDebug("Approov message signing: created timestamp {Created} ahead of server time {Now}", createdInstant.ToUnixTimeSeconds(), now.ToUnixTimeSeconds());
                return (false, "Signature 'created' timestamp is in the future");
            }
        }

        if (_validationOptions.SignatureRequireExpires && !metadata.Expires.HasValue)
        {
            _logger.LogDebug("Approov message signing: missing expires timestamp");
            return (false, "Signature missing 'expires' parameter");
        }

        if (metadata.Expires.HasValue)
        {
            var expiresInstant = DateTimeOffset.FromUnixTimeSeconds(metadata.Expires.Value);
            if (expiresInstant + _validationOptions.SignatureAllowedClockSkew < now)
            {
                _logger.LogDebug("Approov message signing: expires timestamp {Expires} has elapsed (now {Now})", expiresInstant.ToUnixTimeSeconds(), now.ToUnixTimeSeconds());
                return (false, "Signature has expired");
            }
        }

        if (metadata.Created.HasValue && metadata.Expires.HasValue && metadata.Expires.Value < metadata.Created.Value)
        {
            _logger.LogDebug("Approov message signing: expires {Expires} precedes created {Created}", metadata.Expires.Value, metadata.Created.Value);
            return (false, "Signature 'expires' parameter precedes the 'created' timestamp");
        }

        return (true, null);
    }

    private static bool TryConvertToLong(object value, out long result)
    {
        switch (value)
        {
            case long longValue:
                result = longValue;
                return true;
            case int intValue:
                result = intValue;
                return true;
            case short shortValue:
                result = shortValue;
                return true;
            default:
                result = default;
                return false;
        }
    }

    private static bool IsComponentCovered(IReadOnlyList<ParsedItem> components, string identifier)
    {
        return components.Any(component =>
            component.Value is string componentIdentifier &&
            string.Equals(componentIdentifier, identifier, StringComparison.OrdinalIgnoreCase));
    }

    // Reconstructs the canonical message according to the Structured Field component list supplied by the client.
    private (bool Success, string? Payload, string? Error) BuildCanonicalMessage(ApproovSignedRequest request, IReadOnlyList<ParsedItem> components, IReadOnlyDictionary<string, object>? parameters)
    {
        var lines = new List<string>();
        foreach (var component in components)
        {
            if (component.Value is not string identifier)
            {
                return (false, null, $"Unsupported component type '{component.Value?.GetType()}' in signature input");
            }

            string value;
            try
            {
                value = ResolveComponentValue(request, identifier, component.Parameters);
            }
            catch (MessageSignatureException ex)
            {
                _logger.LogDebug("Approov message signing: failed to resolve component {Identifier} - {Error}", identifier, ex.Message);
                return (false, null, ex.Message);
            }

            _logger.LogTrace("Approov message signing: resolved component {Identifier} with value length {Length}", identifier, value.Length);
            // Serialise the Structured Field token back into its textual label (e.g. "@method").
            var label = StructuredFieldFormatter.SerializeItem(component);
            lines.Add($"{label}: {value}");
        }

        var signatureParams = StructuredFieldFormatter.SerializeInnerList(components, parameters);
        lines.Add("\"@signature-params\": " + signatureParams);

        var payload = string.Join('\n', lines);
        return (true, payload, (string?)null);
    }

    // Ensures any Content-Digest headers align with the current request body bytes.
    private (bool Success, string? Error) VerifyContentDigest(ApproovSignedRequest request)
    {
        var contentDigestHeader = StructuredFieldFormatter.CombineHeaderValues(request.GetHeaderValues("Content-Digest"));
        if (string.IsNullOrWhiteSpace(contentDigestHeader))
        {
            return (true, null);
        }

        var parseError = SfvParser.ParseDictionary(contentDigestHeader, out var digestDictionary);
        if (parseError.HasValue || digestDictionary is null)
        {
            return (false, $"Failed to parse content-digest header: {parseError?.Message ?? "Unknown error"}");
        }

        var bodyBytes = request.Body;

        foreach (var entry in digestDictionary)
        {
            if (!SupportedContentDigestAlgorithms.Contains(entry.Key))
            {
                return (false, $"Unsupported content-digest algorithm '{entry.Key}'");
            }

            if (entry.Value.Value is not string && entry.Value.Value is not ReadOnlyMemory<byte>)
            {
                return (false, "Content-Digest entry is not a string or byte sequence");
            }

            var expectedDigest = entry.Value.Value is string text
                ? text
                : ":" + Convert.ToBase64String(((ReadOnlyMemory<byte>)entry.Value.Value!).ToArray()) + ":";

            var actualDigest = ComputeDigest(entry.Key, bodyBytes);
            _logger.LogTrace(
                "Approov message signing: content-digest check algorithm={Algorithm} expected={Expected} actual={Actual}",
                entry.Key,
                expectedDigest,
                actualDigest);

            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expectedDigest), Encoding.ASCII.GetBytes(actualDigest)))
            {
                return (false, $"Content digest verification failed for algorithm '{entry.Key}'");
            }
        }

        return (true, null);
    }

    // Computes the HTTP message digest value for supported algorithms.
    private static string ComputeDigest(string algorithm, byte[] body)
    {
        return algorithm.Equals("sha-512", StringComparison.OrdinalIgnoreCase)
            ? ":" + Convert.ToBase64String(SHA512.HashData(body)) + ":"
            : ":" + Convert.ToBase64String(SHA256.HashData(body)) + ":";
    }

    // Imports the EC public key and validates the raw signature bytes against the canonical payload.
    private bool TryVerifySignature(string publicKeyBase64, ReadOnlyMemory<byte> signatureBytes, byte[] canonicalPayload)
    {
        try
        {
            var publicKey = Convert.FromBase64String(publicKeyBase64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);

            var signature = signatureBytes.ToArray();
            var verified = ecdsa.VerifyData(canonicalPayload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (!verified)
            {
                _logger.LogDebug("Approov message signing: signature verification failed for payload length {Length}", canonicalPayload.Length);
            }

            return verified;
        }
        catch (FormatException ex)
        {
            _logger.LogWarning("Invalid public key format - {Message}", ex.Message);
            return false;
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex, "Cryptographic failure during signature verification");
            return false;
        }
    }

    // Resolves each structured field component identifier into the actual HTTP request value.
    private string ResolveComponentValue(ApproovSignedRequest request, string identifier, IReadOnlyDictionary<string, object>? parameters)
    {
        switch (identifier)
        {
            case "@method":
                return request.Method;
            case "@target-uri":
                return request.TargetUri;
            case "@authority":
                return request.Host;
            case "@scheme":
                return request.Scheme;
            case "@path":
                return request.Path;
            case "@query":
                return string.IsNullOrEmpty(request.Query) ? "?" : request.Query;
            case "@request-target":
                return request.RequestTarget;
            case "@query-param":
                return ResolveQueryParam(request, parameters);
            default:
                return ResolveHeaderComponent(request, identifier, parameters);
        }
    }

    private static string ResolveQueryParam(ApproovSignedRequest request, IReadOnlyDictionary<string, object>? parameters)
    {
        if (parameters is null || !parameters.TryGetValue("name", out var value) || value is not string name)
        {
            throw new MessageSignatureException("@query-param requires a 'name' parameter");
        }

        var matchingValues = request.QueryParameterItems
            .Where(parameter => string.Equals(parameter.EncodedName, name, StringComparison.Ordinal))
            .ToArray();

        if (matchingValues.Length == 0)
        {
            throw new MessageSignatureException($"Missing query parameter '{name}' for @query-param component");
        }

        if (matchingValues.Length > 1)
        {
            throw new MessageSignatureException($"Query parameter '{name}' occurs multiple times and cannot be used with @query-param");
        }

        return matchingValues[0].EncodedValue;
    }

    private string ResolveHeaderComponent(ApproovSignedRequest request, string headerName, IReadOnlyDictionary<string, object>? parameters)
    {
        var values = request.GetHeaderValues(headerName);
        if (values.Count == 0)
        {
            throw new MessageSignatureException($"Missing header '{headerName}' referenced in signature");
        }

        if (parameters is null || parameters.Count == 0)
        {
            return StructuredFieldFormatter.CombineHeaderValues(values);
        }

        if (parameters.TryGetValue("sf", out var sfValue) && sfValue is bool sf && sf)
        {
            return SerializeStructuredFieldHeader(headerName, values);
        }

        if (parameters.TryGetValue("key", out var keyValue) && keyValue is string key)
        {
            var raw = StructuredFieldFormatter.CombineHeaderValues(values);
            var parseError = SfvParser.ParseDictionary(raw, out var dictionary);
            if (parseError.HasValue || dictionary is null)
            {
                throw new MessageSignatureException($"Failed to parse header '{headerName}' as dictionary: {parseError?.Message ?? "unknown error"}");
            }

            if (!dictionary.TryGetValue(key, out var item))
            {
                throw new MessageSignatureException($"Header '{headerName}' dictionary missing key '{key}'");
            }

            return StructuredFieldFormatter.SerializeItem(item);
        }

        return StructuredFieldFormatter.CombineHeaderValues(values);
    }

    private static string SerializeStructuredFieldHeader(string headerName, IReadOnlyList<string> values)
    {
        var raw = StructuredFieldFormatter.CombineHeaderValues(values);
        var dictionaryError = SfvParser.ParseDictionary(raw, out var dictionary);
        if (!dictionaryError.HasValue && dictionary is not null)
        {
            return StructuredFieldFormatter.SerializeDictionary(dictionary);
        }

        var listError = SfvParser.ParseList(raw, out var list);
        if (!listError.HasValue && list is not null)
        {
            return StructuredFieldFormatter.SerializeList(list);
        }

        var itemError = SfvParser.ParseItem(raw, out var item);
        if (!itemError.HasValue)
        {
            return StructuredFieldFormatter.SerializeItem(item);
        }

        var errorMessage = dictionaryError?.Message ?? listError?.Message ?? itemError?.Message ?? "unknown error";
        throw new MessageSignatureException($"Failed to parse header '{headerName}' as structured field value: {errorMessage}");
    }
}

public sealed record MessageSignatureResult(bool Success, string? Error, string? CanonicalMessage)
{
    public static MessageSignatureResult Failure(string error) => new(false, error, null);
    public static MessageSignatureResult Succeeded(string canonical) => new(true, null, canonical);
}

public sealed class MessageSignatureException : Exception
{
    public MessageSignatureException(string message) : base(message)
    {
    }
}
