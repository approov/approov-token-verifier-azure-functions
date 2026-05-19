namespace Approov.Validation;

using System.Collections.ObjectModel;
using System.Text;

public sealed class ApproovSignedRequest
{
    private readonly Dictionary<string, IReadOnlyList<string>> _headers;

    public ApproovSignedRequest(
        string method,
        string scheme,
        string host,
        string path,
        string query,
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        byte[] body,
        string? originalUrl = null)
    {
        Method = string.IsNullOrWhiteSpace(method) ? string.Empty : method.ToUpperInvariant();
        Scheme = scheme.Trim();
        Host = host.Trim();
        Path = string.IsNullOrWhiteSpace(path) ? "/" : path.Trim();
        Query = NormalizeQuery(query);
        Body = body;
        OriginalUrl = string.IsNullOrWhiteSpace(originalUrl) ? null : originalUrl.Trim();
        _headers = headers.ToDictionary(
            entry => entry.Key,
            entry => entry.Value,
            StringComparer.OrdinalIgnoreCase);
        Headers = new ReadOnlyDictionary<string, IReadOnlyList<string>>(_headers);
        QueryParameters = ParseQuery(Query);
        QueryParameterItems = ParseQueryItems(Query);
    }

    public string Method { get; }
    public string Scheme { get; }
    public string Host { get; }
    public string Path { get; }
    public string Query { get; }
    public byte[] Body { get; }
    public string? OriginalUrl { get; }
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Headers { get; }
    public IReadOnlyDictionary<string, IReadOnlyList<string>> QueryParameters { get; }
    public IReadOnlyList<ApproovQueryParameter> QueryParameterItems { get; }

    public string RequestTarget => Path + Query;

    public string TargetUri => OriginalUrl ?? $"{Scheme}://{Host}{RequestTarget}";

    public IReadOnlyList<string> GetHeaderValues(string headerName)
    {
        return _headers.TryGetValue(headerName, out var values) ? values : Array.Empty<string>();
    }

    public string GetHeaderValue(string headerName)
    {
        return StructuredFieldFormatter.CombineHeaderValues(GetHeaderValues(headerName));
    }

    private static string NormalizeQuery(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return string.Empty;
        }

        var trimmed = query.Trim();
        return trimmed.StartsWith("?", StringComparison.Ordinal) ? trimmed : "?" + trimmed;
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<string>> ParseQuery(string query)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var normalized = query.TrimStart('?');
        if (normalized.Length == 0)
        {
            return new ReadOnlyDictionary<string, IReadOnlyList<string>>(
                new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase));
        }

        foreach (var pair in normalized.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separatorIndex = pair.IndexOf('=', StringComparison.Ordinal);
            var rawName = separatorIndex >= 0 ? pair[..separatorIndex] : pair;
            var rawValue = separatorIndex >= 0 ? pair[(separatorIndex + 1)..] : string.Empty;
            var name = DecodeQueryComponent(rawName);
            var value = DecodeQueryComponent(rawValue);

            if (!result.TryGetValue(name, out var values))
            {
                values = new List<string>();
                result[name] = values;
            }

            values.Add(value);
        }

        return new ReadOnlyDictionary<string, IReadOnlyList<string>>(
            result.ToDictionary(entry => entry.Key, entry => (IReadOnlyList<string>)entry.Value, StringComparer.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<ApproovQueryParameter> ParseQueryItems(string query)
    {
        var result = new List<ApproovQueryParameter>();
        var normalized = query.TrimStart('?');
        if (normalized.Length == 0)
        {
            return result;
        }

        foreach (var pair in normalized.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separatorIndex = pair.IndexOf('=', StringComparison.Ordinal);
            var rawName = separatorIndex >= 0 ? pair[..separatorIndex] : pair;
            var rawValue = separatorIndex >= 0 ? pair[(separatorIndex + 1)..] : string.Empty;
            var name = EncodeQueryComponentForSignature(DecodeQueryComponent(rawName));
            var value = EncodeQueryComponentForSignature(DecodeQueryComponent(rawValue));

            result.Add(new ApproovQueryParameter(name, value));
        }

        return result;
    }

    private static string DecodeQueryComponent(string value)
    {
        return Uri.UnescapeDataString(value.Replace("+", " ", StringComparison.Ordinal));
    }

    private static string EncodeQueryComponentForSignature(string value)
    {
        return Uri.EscapeDataString(value);
    }
}

public sealed record ApproovQueryParameter(string EncodedName, string EncodedValue);
