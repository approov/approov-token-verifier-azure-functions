# Approov Azure Function Validation

This solution implements an Azure Functions based Approov verifier for Azure API Management (APIM). APIM calls the Function before forwarding to a backend API. The Function owns all Approov validation: token signature/expiry, optional token binding, required message signing, and content digest checks.

## Projects

- `src/Approov.Validation`: reusable validation library.
- `src/Approov.Validation.Functions`: .NET 8 isolated Azure Function host exposing `/api/approov/verify`.
- `tests/Approov.Validation.Tests`: validator and APIM-metadata adapter tests.
- `apim/approov-validation-fragment.xml`: inbound APIM policy fragment.

## Function Configuration

Set these app settings on the Function App:

| Setting | Default | Notes |
| --- | --- | --- |
| `APPROOV_BASE64_SECRET` | required | Use a Key Vault reference in customer deployments. |
| `APPROOV_TOKEN_BINDING_HEADERS` | empty | Comma-delimited list, for example `Authorization`. |
| `APPROOV_MESSAGE_SIGNING_MODE` | `required` | Supported: `required`, `optional`, `disabled`. |
| `APPROOV_SIGNATURE_REQUIRE_CREATED` | `true` | Requires `created` in `Signature-Input`. |
| `APPROOV_SIGNATURE_REQUIRE_EXPIRES` | `false` | Requires `expires` when true. |
| `APPROOV_SIGNATURE_MAX_AGE_SECONDS` | `300` | Signature freshness window. |
| `APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS` | `60` | Allowed client/server time drift. |
| `APPROOV_MAX_BODY_BYTES` | `10485760` | Function rejects larger mirrored request bodies. |

## APIM Integration

1. Deploy the Function App on a Premium plan for customer-facing use.
2. Enable Microsoft Entra authentication on the Function App.
3. Enable a managed identity on APIM and grant it access to call the Function App.
4. Add named values:
   - `approov-validation-function-url`
   - `approov-validation-function-audience`
5. Include `apim/approov-validation-fragment.xml` in the inbound APIM policy for protected APIs.

The APIM fragment mirrors the incoming request to the Function using `send-request mode="copy"` and overwrites trusted `X-Approov-Original-*` metadata headers. The Function uses those headers to reconstruct the URL the mobile app signed, not the Function URL.

## Local Verification

```bash
dotnet build ApproovAzureValidation.sln
dotnet test ApproovAzureValidation.sln
```
