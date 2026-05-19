# Samples

Samples are not part of the production Approov verifier deployment.

They are included only to make demos and integration tests reproducible when a customer backend is not available. Customer production environments should deploy the verifier Function and APIM policy, then point APIM at the customer's real backend API.

## Approov.ShapesApi.Functions

`Approov.ShapesApi.Functions` is a small Azure Functions backend that mimics the public Approov Shapes demo response for the existing quickstart API key.

Build it explicitly when needed:

```bash
dotnet build samples/Approov.ShapesApi.Functions/Approov.ShapesApi.Functions.csproj --configuration Release
```

Deploy it only in demo or test resource groups.
