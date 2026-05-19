namespace Approov.ShapesApi.Functions;

using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

public sealed class ShapesFunction
{
    private const string ExpectedApiKey = "yXClypapWNHIifHUWmBIyPFAm";

    [Function("GetShapes")]
    public static async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "head", "options", Route = "v1/shapes")]
        HttpRequestData req)
    {
        if (string.Equals(req.Method, "OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            var optionsResponse = req.CreateResponse(HttpStatusCode.OK);
            AddCommonHeaders(optionsResponse);
            optionsResponse.Headers.Add("Allow", "HEAD, GET");
            optionsResponse.Headers.Add("Content-Type", "text/plain; charset=utf-8");
            return optionsResponse;
        }

        var response = HasValidApiKey(req) switch
        {
            true => req.CreateResponse(HttpStatusCode.OK),
            false when HasApiKey(req) => req.CreateResponse(HttpStatusCode.BadRequest),
            _ => req.CreateResponse(HttpStatusCode.BadRequest)
        };

        AddCommonHeaders(response);
        response.Headers.Add("Content-Type", "application/json; charset=utf-8");

        if (!string.Equals(req.Method, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            var body = HasValidApiKey(req)
                ? """{"shape":"Square","status":"Square (api key protected)"}"""
                : HasApiKey(req)
                    ? """{"status":"invalid api key"}"""
                    : """{"status":"missing the api key in the request"}""";
            await response.WriteStringAsync(body);
        }

        return response;
    }

    private static bool HasApiKey(HttpRequestData req)
    {
        return req.Headers.TryGetValues("Api-Key", out var values) &&
            values.Any(value => !string.IsNullOrWhiteSpace(value));
    }

    private static bool HasValidApiKey(HttpRequestData req)
    {
        return req.Headers.TryGetValues("Api-Key", out var values) &&
            values.Any(value => string.Equals(value.Trim(), ExpectedApiKey, StringComparison.Ordinal));
    }

    private static void AddCommonHeaders(HttpResponseData response)
    {
        response.Headers.Add("Access-Control-Allow-Origin", "*");
        response.Headers.Add("Vary", "Origin");
    }
}
