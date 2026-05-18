# Azure Testing Plan

Local CI covers the validation library and Function HTTP wrapper. A real Azure pass is still needed because APIM policy execution, managed identity, Function App authentication, Key Vault references, and network routing cannot be proven by unit tests.

## Test Environment

Use a temporary Azure resource group with:

- Azure API Management, preferably Developer tier for validation.
- Azure Function App on Premium plan for production-like latency testing.
- Azure Storage account required by the Function App.
- Application Insights for APIM/Function telemetry.
- Azure Key Vault containing `APPROOV_BASE64_SECRET`.
- Echo backend, such as a small App Service, Container App, or test Function that returns received method, path, query, headers, and body hash.
- APIM system-assigned managed identity allowed to call the verifier Function.
- Function App Microsoft Entra/App Service Authentication configured to accept only APIM's managed identity.

## Functional Scenarios

- Valid Approov token, valid message signature, valid body digest reaches the echo backend.
- Missing/expired/tampered Approov token returns `401` from APIM and does not reach backend.
- Missing `Signature` or `Signature-Input` returns `401`.
- Tampered path, query, header, or body returns `401`.
- Stale and future `created` timestamps return `401`.
- Token binding enabled with matching `Authorization` reaches backend.
- Missing token binding header returns `400` from the verifier/APIM path.
- Mismatched token binding header returns `401`.
- Oversized request body returns `413`.
- CORS `OPTIONS` preflight bypasses validation as configured.
- Spoofed inbound `X-Approov-Original-*` headers are overwritten before the verifier call.
- `Approov-Token`, `Signature`, `Signature-Input`, and `Content-Digest` are stripped before backend.
- Backend receives only trusted `X-Approov-Verified`, optional `X-Approov-Device-Id`, and optional `X-Approov-Token-Expiry`.

## Operational Scenarios

- Function App unavailable: APIM returns a controlled `401`/gateway rejection and does not reach backend.
- Managed identity permission removed: APIM rejects requests and trace shows authentication failure.
- Key Vault secret missing or malformed: Function returns configuration error; APIM blocks request.
- Function cold start and warm latency measured at p50/p95/p99.
- Concurrent traffic test validates APIM timeout and Function scaling behavior.
- Application Insights logs include reason codes but no token, signature, authorization header, or body content.

## Effort Estimate

- Basic Azure smoke test: 0.5-1 day once Azure access is available.
- Full functional APIM + Function + echo backend test pass: 2-3 days.
- Production-like latency, failure-mode, and identity/Key Vault hardening tests: 3-5 additional days.
- Automated Azure integration test pipeline with ephemeral resource group teardown: 1-2 weeks, depending on the customer's Azure governance and permissions.

## Acceptance Criteria

- CI passes on every push and pull request.
- Azure smoke test proves APIM can call the Function using managed identity.
- All invalid Approov cases are blocked before backend.
- All valid signed requests reach backend with body intact.
- Backend receives no raw Approov token or signature headers.
- Telemetry is sufficient to distinguish request failures from configuration/deployment failures without logging secrets.
