# Yandex Cloud VM Pricing: Programmatic Access Research

## Summary

Yandex Cloud **does have** a public billing REST/gRPC API (`billing.api.cloud.yandex.net`) that exposes all pricing SKUs programmatically. This is the canonical machine-readable source. The pricing web page (`yandex.cloud/ru/prices`) is a dynamic React calculator that requires a real browser and does NOT embed `__NEXT_DATA__` with prices. The `yc` CLI exposes some billing commands but not a direct SKU-list command. The docs GitHub repo has pricing markdown but uses template variables, not raw numbers.

---

## 1. Official Billing REST API (Recommended)

### Endpoint

```
GET https://billing.api.cloud.yandex.net/billing/v1/skus
```

This is the **canonical programmatic source** for all Yandex Cloud pricing. It returns every SKU (compute cores, RAM, disk, GPU, network, etc.) with current prices.

### Authentication

Requires an **IAM token** in the `Authorization` header.

**Option A — OAuth token exchange (interactive user):**
```bash
curl -d '{"yandexPassportOauthToken":"<YOUR_OAUTH_TOKEN>"}' \
     https://iam.api.cloud.yandex.net/iam/v1/tokens
# Returns: {"iamToken": "t1.9e...", "expiresAt": "..."}
```

**Option B — Service account (daemon/automated):**
1. Create a service account in the Yandex Cloud console
2. Generate a key pair (`yc iam key create --service-account-id ...`)
3. Sign a JWT and exchange it for an IAM token:
```bash
curl --request POST \
     --header 'Content-Type: application/json' \
     --data '{"jwt": "<SIGNED_JWT>"}' \
     https://iam.api.cloud.yandex.net/iam/v1/tokens
```

IAM tokens expire after **12 hours** and must be refreshed.

**Option C — yc CLI shortcut (if yc is installed):**
```bash
export IAM_TOKEN=$(yc iam create-token)
```

### Request Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `currency` | string | YES | `RUB`, `USD`, or `KZT` |
| `billingAccountId` | string | no | If set, returns contract-specific prices instead of public street prices |
| `filter` | string | no | Filter expression, max 1000 chars. Currently only `serviceId` filtering is documented (see below) |
| `pageSize` | int64 | no | Max results per page, up to 1000 |
| `pageToken` | string | no | Pagination token from previous response |

### Filter Syntax

The `filter` parameter uses the format:
```
serviceId="<SERVICE_ID>"
```

Example — fetch only Compute Cloud SKUs:
```
filter=serviceId="<compute_service_id>"
```

Note: The actual Compute Cloud `serviceId` value is an opaque identifier (like `dn28hpu6268356q0j8mk`) returned in each SKU's `service_id` field. You can discover it by making one unfiltered request and inspecting the returned SKUs.

### Example Request

```bash
export IAM_TOKEN="<your_iam_token>"

curl -H "Authorization: Bearer ${IAM_TOKEN}" \
     "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB&pageSize=1000"
```

With compute filter (replace with real service ID):
```bash
curl -H "Authorization: Bearer ${IAM_TOKEN}" \
     "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB&filter=serviceId%3D%22<COMPUTE_SERVICE_ID>%22&pageSize=1000"
```

### Response JSON Structure

```json
{
  "skus": [
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "serviceId": "string",
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
                  "unitPrice": "0.8064",
                  "currency": "RUB"
                }
              ]
            }
          ]
        }
      ]
    }
  ],
  "nextPageToken": "string"
}
```

### Field Descriptions

**Sku object:**

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique SKU identifier |
| `name` | string | Human-readable name (e.g., "Intel Broadwell. 100% vCPU") |
| `description` | string | Detailed description |
| `serviceId` | string | Opaque service identifier (use to filter by service) |
| `pricingUnit` | string | Unit: `core*hour`, `gbyte*hour`, `hour`, etc. |
| `pricingVersions` | array | List of pricing periods (historical + current) |

**PricingVersion object:**

| Field | Type | Description |
|---|---|---|
| `type` | enum | `STREET_PRICE` (public) or `CONTRACT_PRICE` (account-specific) |
| `effectiveTime` | timestamp | When this pricing version became active |
| `pricingExpressions` | array | The actual rates |

**Rate object:**

| Field | Type | Description |
|---|---|---|
| `startPricingQuantity` | string | Tier start (usually "0" for a single tier) |
| `unitPrice` | string | Price per pricingUnit |
| `currency` | string | `RUB`, `USD`, or `KZT` |

### Pagination

If `nextPageToken` is non-empty in the response, pass it as `pageToken` in the next request:
```bash
curl -H "Authorization: Bearer ${IAM_TOKEN}" \
     "https://billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB&pageSize=1000&pageToken=<NEXT_PAGE_TOKEN>"
```

### Get Single SKU

```
GET https://billing.api.cloud.yandex.net/billing/v1/skus/{id}?currency=RUB
```

---

## 2. gRPC API (Alternative to REST)

Defined in the official `yandex-cloud/cloudapi` protobuf repository.

**Proto package:** `yandex.cloud.billing.v1`
**Service:** `SkuService`

RPC methods:
- `Get(GetSkuRequest) returns Sku`
- `List(ListSkusRequest) returns ListSkusResponse`

Go SDK: `github.com/yandex-cloud/go-genproto/yandex/cloud/billing/v1`

For a Rust daemon, the REST API is simpler (just `reqwest` + `serde_json`).

---

## 3. Compute Cloud Pricing Categories (from docs)

The compute pricing page lists these resource categories as billable:

| Resource | Pricing Unit | Notes |
|---|---|---|
| vCPU (Intel Broadwell, Cascade Lake, Ice Lake, AMD Zen 3/4) | `core*hour` | Per platform/guarantee level |
| RAM | `gbyte*hour` | Per GB per hour |
| GPU (if applicable) | `hour` | Per GPU unit |
| Boot/data disk (HDD) | `gbyte*hour` | Per GB stored |
| Boot/data disk (SSD) | `gbyte*hour` | Higher rate |
| Non-replicated SSD | `gbyte*hour` | Higher rate |
| Snapshot storage | `gbyte*hour` | |
| Public IP address | `hour` | Per address |
| Outbound traffic | `gbyte` | |
| Software-accelerated network | requires extra vCPU | 2–4 cores depending on platform |

Platforms supported:
- Intel Broadwell (`standard-v1`)
- Intel Cascade Lake (`standard-v2`)
- Intel Ice Lake (`standard-v3`)
- Intel Ice Lake Compute Optimized (`highfreq-v3`)
- AMD Zen 3 (`standard-v3`)
- AMD Zen 4 (`standard-v4`)
- AMD Zen 4 Compute-Optimized

---

## 4. Web Page Analysis (`yandex.cloud/ru/prices`)

**Does NOT work with headless Chrome / curl.**

The page is a React/Next.js dynamic calculator. Key findings:
- Protected by Yandex's bot verification (CAPTCHA/RUM check) — `curl` returns a verification HTML page
- Does **not** embed `__NEXT_DATA__` with pricing JSON
- Prices are loaded via XHR/API calls after the browser passes verification
- The verification system checks browser fingerprint and performs JavaScript challenges
- Attempting to scrape this page is not viable for a daemon

**Conclusion:** Do not use this page. Use the Billing REST API instead.

---

## 5. `yc` CLI

The `yc` CLI does **not** have a `yc billing sku list` command exposed in the documented command tree. The billing API is only accessible via:
- Direct REST calls (`curl`)
- gRPC clients
- SDK calls

The CLI does have `yc iam create-token` which is useful for generating IAM tokens for daemon authentication.

**Useful CLI commands for setup:**
```bash
# Install CLI
curl https://storage.yandexcloud.net/yandexcloud-yc/install.sh | bash

# Configure profile
yc init

# Get IAM token (valid 12h)
yc iam create-token

# Create service account for daemon
yc iam service-account create --name pricing-daemon

# Create API key for service account
yc iam key create --service-account-name pricing-daemon --output key.json
```

---

## 6. GitHub Docs Repo (Static Markdown)

Repository: `https://github.com/yandex-cloud/docs`

File: `en/compute/pricing.md`

**Not usable for programmatic pricing.** The markdown uses template variables like `{{ pcs|compute }}` instead of actual numbers. Real prices are injected at render time by the documentation website. This file is only useful for understanding the structure of pricing (what resources are charged), not for getting actual figures.

---

## 7. Recommended Architecture for the Daemon

```
Daily cron job:
  1. Refresh IAM token
     POST https://iam.api.cloud.yandex.net/iam/v1/tokens
     body: {"yandexPassportOauthToken": "<oauth>"}
     → store iamToken (valid 12h, refresh daily is fine)

  2. Fetch all compute SKUs (paginated)
     GET https://billing.api.cloud.yandex.net/billing/v1/skus
       ?currency=RUB
       &pageSize=1000
       &filter=serviceId%3D%22<COMPUTE_SERVICE_ID>%22
     → iterate nextPageToken until empty

  3. Parse and store:
     - sku.id
     - sku.name
     - sku.pricingUnit
     - sku.pricingVersions[last].pricingExpressions[0].rates[0].unitPrice

  4. To discover COMPUTE_SERVICE_ID on first run:
     Fetch all SKUs unfiltered, find any SKU whose name contains "Broadwell"
     or "vCPU" — record its serviceId for future filtered fetches.
```

**Currencies available:** `RUB`, `USD`, `KZT`

**No billing account required** for public (street) prices. `billingAccountId` is optional and only needed for custom contract pricing.

---

## Sources

- [Yandex Cloud Billing API — sku_service.proto (GitHub)](https://github.com/yandex-cloud/cloudapi/blob/master/yandex/cloud/billing/v1/sku_service.proto)
- [Yandex Cloud Billing API — sku.proto (GitHub)](https://github.com/yandex-cloud/cloudapi/blob/master/yandex/cloud/billing/v1/sku.proto)
- [Billing API REST: Sku.List (Russian docs)](https://cloud.yandex.ru/ru/docs/billing/api-ref/Sku/list)
- [Billing API REST: Sku.List (English docs)](https://yandex.cloud/ru/docs/billing/api-ref/Sku/list)
- [go-genproto billing/v1 package](https://pkg.go.dev/github.com/yandex-cloud/go-genproto/yandex/cloud/billing/v1)
- [Yandex Cloud Compute Pricing (docs)](https://cloud.yandex.com/en/docs/compute/pricing)
- [IAM Token Creation](https://yandex.cloud/en/docs/iam/operations/iam-token/create)
- [Yandex Cloud API Overview](https://yandex.cloud/en/docs/overview/api)
- [cloudapi GitHub repo](https://github.com/yandex-cloud/cloudapi)
- [Yandex Cloud Prices Calculator (web)](https://yandex.cloud/en/prices)
