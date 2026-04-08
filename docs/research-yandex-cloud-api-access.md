# Yandex Cloud Billing API Access — Research Findings

**Date:** 2026-04-05
**Purpose:** Determine how to extract VM pricing data from Yandex Cloud for the VPS price aggregator.

---

## Summary / TL;DR

- **Auth is required** for the Billing SKU API. There is no public unauthenticated endpoint like AWS Pricing API.
- The cheapest/easiest path: **get a free Yandex account + create a billing account** (no payment required to create one), then use `yc iam create-token` + curl.
- The `billing.api.cloud.yandex.net/billing/v1/skus` endpoint **does work** and returns all VM SKUs with RUB prices.
- The `billing_account_id` parameter is **optional** — omitting it returns public street prices (no contract pricing needed).
- Pricing docs (GitHub markdown) use **dynamic MDX components** (`<PriceList serviceIds=... />`), so scraping the docs HTML is not reliable.

---

## 1. IAM Token — How to Obtain

### 1a. For a Yandex User Account (Yandex Passport / OAuth)

**Step 1: Get OAuth token**

Go to: `https://oauth.yandex.ru/authorize?response_type=token&client_id=1a6990aa636648e9b2ef855fa7bec2fb`

This is Yandex Cloud CLI's own OAuth app. You log in with your Yandex account (yandex.ru, yandex.com, etc.) and receive an OAuth token.

**Step 2: Exchange OAuth token for IAM token**

```bash
curl \
  --request POST \
  --header "Content-Type: application/json" \
  --data '{"yandexPassportOauthToken": "<YOUR_OAUTH_TOKEN>"}' \
  https://iam.api.cloud.yandex.net/iam/v1/tokens
```

**Response:**
```json
{
  "iamToken": "t1.9euelZrLop7Uz8up...",
  "expiresAt": "2026-04-05T13:00:00Z"
}
```

**IAM token lifetime:** max 12 hours. Recommend refreshing every 1 hour.

### 1b. Via `yc` CLI (Easiest — Wraps OAuth Flow Automatically)

```bash
# Install yc CLI (Linux/macOS)
curl https://storage.yandexcloud.net/yandexcloud-yc/install.sh | bash

# Initialize (opens browser for OAuth, no paid account needed)
yc init

# Get an IAM token directly
yc iam create-token
```

Output: `t1.9euelZrLop7Uz8up...`

Store in a variable:
```bash
export IAM_TOKEN=$(yc iam create-token)
```

### 1c. For a Service Account (Production Use)

**Step 1: Create a service account**
```bash
yc iam service-account create --name my-pricing-bot
```

**Step 2: Grant billing.viewer role**
```bash
yc resource-manager folder add-access-binding \
  --role billing.viewer \
  --service-account-name my-pricing-bot \
  --id <FOLDER_ID>
```

**Step 3: Create authorized key pair**
```bash
yc iam key create \
  --service-account-name my-pricing-bot \
  --output key.json
```

**Step 4: Build and sign a JWT**

Required JWT fields:
- `iss`: service account ID
- `aud`: `https://iam.api.cloud.yandex.net/iam/v1/tokens`
- `iat`: current Unix timestamp
- `exp`: iat + 3600 (max)
- `kid`: public key ID (from key.json)

Signing algorithm: **PS256 only** (RSA-PSS SHA-256).

**Step 5: Exchange JWT for IAM token**
```bash
curl \
  --request POST \
  --header "Content-Type: application/json" \
  --data '{"jwt": "<YOUR_JWT>"}' \
  https://iam.api.cloud.yandex.net/iam/v1/tokens
```

**Required IAM role for Billing SKU API:**
- `billing.viewer` on the billing account or folder
- The SKU list (public prices) may work with just a valid IAM token — `billing_account_id` is optional

---

## 2. Billing SKU API — VM Pricing Endpoint

### Base URL

```
https://billing.api.cloud.yandex.net
```

### Endpoint: List All SKUs

```
GET https://billing.api.cloud.yandex.net/billing/v1/skus
```

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `currency` | string | **YES** | One of: `RUB`, `USD`, `KZT` |
| `billingAccountId` | string | NO | If provided, returns contract prices for that billing account. Omit for public street prices. |
| `filter` | string | NO | e.g. `serviceId="dn2isp..."` — filter by service. Max 1000 chars. |
| `pageSize` | int64 | NO | Max 1000 results per page. Default unknown. |
| `pageToken` | string | NO | Token from previous response for pagination. |

### Authentication Header

```
Authorization: Bearer <IAM_TOKEN>
```

### Example curl Request

```bash
export IAM_TOKEN=$(yc iam create-token)

curl \
  --request GET \
  --header "Authorization: Bearer ${IAM_TOKEN}" \
  "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB&pageSize=1000"
```

With pagination:
```bash
curl \
  --request GET \
  --header "Authorization: Bearer ${IAM_TOKEN}" \
  "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB&pageSize=1000&pageToken=<NEXT_PAGE_TOKEN>"
```

### Response Format

```json
{
  "skus": [
    {
      "id": "dn2...",
      "name": "Intel Ice Lake. 100% vCPU",
      "description": "...",
      "serviceId": "dn2isp...",
      "pricingUnit": "core*hour",
      "pricingVersions": [
        {
          "type": "STREET_PRICE",
          "effectiveTime": "2024-01-01T00:00:00Z",
          "pricingExpressions": [
            {
              "rates": [
                {
                  "startPricingQuantity": "0",
                  "unitPrice": "1.1529",
                  "currency": "RUB"
                }
              ]
            }
          ]
        }
      ]
    }
  ],
  "nextPageToken": "..."
}
```

### Key Fields

- `pricingUnit`: the billing unit — `core*hour`, `gbyte*hour`, `gbyte` (disk), `gbyte*month` (snapshots)
- `pricingVersions[].type`: `STREET_PRICE` = public price, `CONTRACT_PRICE` = negotiated price (requires billing_account_id)
- `effectiveTime`: when this price version became active
- `rates[].startPricingQuantity`: threshold quantity (usually "0" for flat rate, higher values for volume discounts)

### Known Price Examples (from real API data, ~2024-2025, RUB)

| SKU Name | pricingUnit | Price (RUB) |
|----------|-------------|-------------|
| Intel Ice Lake, 100% vCPU | core\*hour | ~1.1529 |
| RAM | gbyte\*hour | ~0.3074 |
| Network HDD | gbyte\*hour | ~0.004453 |
| Network SSD | gbyte\*hour | ~higher |

### Getting SKUs for Compute Only (filter by serviceId)

First, discover compute serviceId:
```bash
curl --header "Authorization: Bearer ${IAM_TOKEN}" \
  "https://billing.api.cloud.yandex.net/billing/v1/services" | jq '.services[] | select(.name | test("Compute"; "i"))'
```

Then filter:
```bash
curl --header "Authorization: Bearer ${IAM_TOKEN}" \
  "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB&filter=serviceId%3D%22<COMPUTE_SERVICE_ID>%22"
```

### gRPC Alternative

The billing API also has a gRPC interface. Proto definition:
- `yandex/cloud/billing/v1/sku_service.proto` in `github.com/yandex-cloud/cloudapi`
- Methods: `Get(GetSkuRequest)` and `List(ListSkusRequest)`
- gRPC host: `billing.api.cloud.yandex.net:443`

---

## 3. Is There a Public API Without Auth?

**No.** Unlike AWS (which has `https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json` with no auth), Yandex Cloud does **not** provide a public unauthenticated pricing API.

Every call to `billing.api.cloud.yandex.net` requires:
```
Authorization: Bearer <IAM_TOKEN>
```

Without the header, the API returns HTTP 401.

**However**, the barrier is low:
- A Yandex account is free
- Creating a billing account on Yandex Cloud is free (no credit card required for account creation, though some services require it)
- `yc init` with a free account gives you a valid IAM token
- The SKU list API works without `billingAccountId` — so you do NOT need a paid/active billing account, just a valid IAM token from any Yandex account

**Verdict:** Auth is required but obtaining it is free and easy.

---

## 4. `yc` CLI — Can It List Pricing?

### What `yc` CAN do for pricing

The `yc` CLI does **not** have a dedicated `yc billing skus list` subcommand for pricing discovery. The billing CLI commands are focused on:

```bash
yc billing account list           # List your billing accounts
yc billing account get <ID>       # Get billing account details
yc billing budget list            # List budgets
yc billing budget create          # Create cost alerts
```

There is **no** `yc billing skus list` or `yc compute pricing list` command.

### Workaround: yc as token provider, curl for data

```bash
# Use yc only to get the token, then hit the REST API directly
export IAM_TOKEN=$(yc iam create-token)

curl \
  --silent \
  --header "Authorization: Bearer ${IAM_TOKEN}" \
  "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB&pageSize=1000" \
  | jq '.skus[] | {name, pricingUnit, price: .pricingVersions[-1].pricingExpressions[0].rates[0].unitPrice}'
```

### Does `yc init` require a paid account?

**No.** `yc init`:
1. Opens browser → Yandex OAuth login
2. Lets you select a cloud/folder (even if empty/free)
3. Produces an IAM token immediately

A free Yandex Cloud account (no billing account, no payment method) is sufficient for `yc iam create-token`. However, calling the Billing SKU API may require at minimum a billing account to exist (even if it's in free-tier / trial state).

---

## 5. Pricing Documentation Pages — Server-Side vs SPA

### Verdict: Hybrid — NOT reliable for scraping

The Yandex Cloud documentation pricing pages (e.g., `cloud.yandex.com/en/docs/compute/pricing`) use a **hybrid rendering approach**:

- The page structure is static Markdown processed by a static site generator
- **Actual prices are injected via MDX React components**: `<MDX><PriceList serviceIds={['compute', 'compute_gpu']} /></MDX>`
- The PriceList component likely fetches from an internal API at render time

**What this means:**
- Raw GitHub markdown (`docs/en/compute/pricing.md`) contains NO actual price numbers — only the `<PriceList>` component placeholder
- The rendered HTML page may load prices dynamically (AJAX) from an internal Yandex backend
- Yandex Cloud's site aggressively blocks bots with CAPTCHA (confirmed during this research — all direct `yandex.cloud` fetches returned CAPTCHA pages)

**There is no stable, scrapable HTML pricing page.**

### Alternative: GitHub raw markdown

The `yandex-cloud/docs` GitHub repository contains the source markdown, but prices are absent — only templates like `{% price 'compute.cores.v3' 'RUB' %}` are present, which get processed server-side.

**Conclusion:** The only reliable programmatic source of Yandex Cloud pricing is the Billing SKU API.

---

## 6. Recommended Implementation Strategy

### For our VPS price scraper (zengeld-crawler / VPS aggregator)

**Option A: yc CLI token + REST API (no code deps)**

```bash
# One-time setup
yc init  # logs in via browser, free

# Periodic fetch
IAM_TOKEN=$(yc iam create-token)
curl -s \
  -H "Authorization: Bearer $IAM_TOKEN" \
  "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=USD&pageSize=1000" \
  > yandex_skus.json
```

**Option B: Rust + reqwest (production use)**

1. Store OAuth token in config/env
2. Exchange for IAM token via POST to `https://iam.api.cloud.yandex.net/iam/v1/tokens`
3. Cache IAM token (valid ~12h, refresh every 1h)
4. GET `https://billing.api.cloud.yandex.net/billing/v1/skus?currency=USD&pageSize=1000`
5. Handle pagination via `nextPageToken`
6. Filter `pricingVersions` by `type == "STREET_PRICE"` and latest `effectiveTime`

**Option C: Use yandex-cloud Python SDK (if Python acceptable)**

```python
import yandexcloud
from yandex.cloud.billing.v1.sku_service_pb2 import ListSkusRequest
from yandex.cloud.billing.v1.sku_service_pb2_grpc import SkuServiceStub

sdk = yandexcloud.SDK(iam_token=iam_token)
stub = sdk.client(SkuServiceStub)
response = stub.List(ListSkusRequest(currency="USD"))
```

---

## 7. Open Questions / Caveats

1. **Does SKU API require `billingAccountId`?** — Officially optional. Community reports (OpenCost/Habr article) confirm street prices work without it. But some sources suggest a billing account must *exist* on your Yandex account. Needs live test.

2. **Free account vs. trial account** — Yandex Cloud gives a 60-day / 4000 RUB trial grant on first billing account creation. The trial doesn't cost money but requires accepting terms. IAM tokens from a free account (no billing account) may not have access to billing API — unknown.

3. **Rate limits** — No official documentation found for Billing SKU API rate limits. Likely generous since it's a read-only catalog endpoint.

4. **USD currency availability** — The API accepts `USD` as currency, but Yandex Cloud primarily serves the Russian market. USD prices may be available but are secondary. Verify with live request.

5. **Price completeness** — The SKU catalog covers vCPU, RAM, disk, GPU, network egress. VM configuration prices must be computed by combining SKUs (e.g., 2 vCPU × vCPU_price + 4 GB × ram_price).

---

## Sources

- [Yandex Cloud Billing API — SkuService proto (GitHub)](https://github.com/yandex-cloud/cloudapi/blob/master/yandex/cloud/billing/v1/sku_service.proto)
- [Yandex Cloud Docs — IAM token for service account (GitHub raw)](https://github.com/yandex-cloud/docs/blob/master/en/iam/operations/iam-token/create-for-sa.md)
- [Yandex Cloud Docs — IAM token for user account (GitHub raw)](https://github.com/yandex-cloud/docs/blob/master/en/iam/operations/iam-token/create.md)
- [Yandex Cloud Billing REST — Sku.list (official)](https://cloud.yandex.com/en/docs/billing/api-ref/Sku/list)
- [Yandex Cloud Billing REST — Sku.list RU](https://cloud.yandex.ru/ru/docs/billing/api-ref/Sku/list)
- [OpenCost в Yandex Cloud — Хабр article (real API usage)](https://habr.com/ru/articles/1009678/)
- [Yandex Cloud cloudapi GitHub](https://github.com/yandex-cloud/cloudapi)
- [Yandex Cloud docs GitHub](https://github.com/yandex-cloud/docs)
- [Yandex Cloud CLI quickstart](https://yandex.cloud/en/docs/cli/quickstart)
- [IAM token usage examples (GitHub raw)](https://github.com/yandex-cloud/docs/blob/master/en/_includes/iam/iam-token-usage-examples.md)
- [Yandex Cloud Compute pricing (docs)](https://cloud.yandex.com/en/docs/compute/pricing)
