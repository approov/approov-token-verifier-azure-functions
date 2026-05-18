namespace Approov.Validation.Tests;

using System.Collections.Specialized;
using System.Net;
using System.Security.Claims;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Functions.Worker.Middleware;

internal sealed class TestHttpRequestData : HttpRequestData
{
    public TestHttpRequestData(
        IReadOnlyDictionary<string, IReadOnlyList<string>> headers,
        byte[] body,
        string method = "POST",
        string url = "https://function.example.com/api/approov/verify")
        : base(new TestFunctionContext())
    {
        Body = new MemoryStream(body);
        Headers = new HttpHeadersCollection();
        foreach (var (name, values) in headers)
        {
            Headers.Add(name, values);
        }

        Method = method;
        Url = new Uri(url);
    }

    public override Stream Body { get; }
    public override HttpHeadersCollection Headers { get; }
    public override IReadOnlyCollection<IHttpCookie> Cookies { get; } = Array.Empty<IHttpCookie>();
    public override Uri Url { get; }
    public override IEnumerable<ClaimsIdentity> Identities { get; } = Array.Empty<ClaimsIdentity>();
    public override string Method { get; }
    public override NameValueCollection Query { get; } = new();

    public override HttpResponseData CreateResponse()
    {
        return new TestHttpResponseData(FunctionContext);
    }
}

internal sealed class TestHttpResponseData : HttpResponseData
{
    public TestHttpResponseData(FunctionContext functionContext)
        : base(functionContext)
    {
    }

    public override HttpStatusCode StatusCode { get; set; }
    public override HttpHeadersCollection Headers { get; set; } = new();
    public override Stream Body { get; set; } = new MemoryStream();
    public override HttpCookies Cookies { get; } = null!;

    public string ReadBody()
    {
        Body.Position = 0;
        using var reader = new StreamReader(Body, leaveOpen: true);
        return reader.ReadToEnd();
    }
}

internal sealed class TestFunctionContext : FunctionContext
{
    private readonly Dictionary<object, object> _items = new();

    public override string InvocationId { get; } = Guid.NewGuid().ToString();
    public override string FunctionId { get; } = "test-function";
    public override TraceContext TraceContext { get; } = null!;
    public override BindingContext BindingContext { get; } = null!;
    public override RetryContext RetryContext { get; } = null!;
    public override IServiceProvider InstanceServices { get; set; } = null!;
    public override FunctionDefinition FunctionDefinition { get; } = null!;
    public override IDictionary<object, object> Items
    {
        get => _items;
        set
        {
            _items.Clear();
            foreach (var item in value)
            {
                _items[item.Key] = item.Value;
            }
        }
    }

    public override IInvocationFeatures Features { get; } = null!;
    public override CancellationToken CancellationToken { get; } = CancellationToken.None;
}
