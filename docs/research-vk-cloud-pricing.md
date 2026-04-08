# VK Cloud Pricing Data Research

## Summary

VK Cloud (formerly Mail.ru Cloud Solutions) pricing is delivered via **two mechanisms**:
1. A **Next.js pricing calculator page** at `https://mcs.mail.ru/pricing/` (redirects to `cloud.vk.com/pricing/`) that embeds static prices in `__NEXT_DATA__` JSON — no separate XHR API call is made.
2. The **OpenStack Nova API** (`GET /flavors`) which returns the actual VM flavor catalog. This requires an authenticated Keystone token.

There is **no public unauthenticated pricing API** — pricing data is either embedded in the page HTML or accessed via OpenStack APIs that require account credentials.

---

## 1. Pricing Page URLs

| Region | URL | Notes |
|--------|-----|-------|
| Russia (primary) | `https://mcs.mail.ru/pricing/` | Redirects to `cloud.vk.com/pricing/` |
| Russia (direct) | `https://cloud.vk.com/pricing/` | Blocked from Anthropic WebFetch |
| Kazakhstan | `https://vkcloud.kz/pricing/` | Accessible, same structure |
| Kazakhstan pricelist | `https://vkcloud.kz/pricelist/` | Static table, accessible |
| Docs (billing) | `https://mcs.mail.ru/docs/ru/additionals/billing/pricing` | Redirects to cloud.vk.com |
| Docs (calculator) | `https://mcs.mail.ru/docs/ru/additionals/billing/pricing/calculator` | Redirects to cloud.vk.com |
| IaaS tariffication | `https://mcs.mail.ru/docs/base/iaas/tariffication` | Redirects to cloud.vk.com |

**Important:** `mcs.mail.ru` is the old domain — all paths 301-redirect to `cloud.vk.com`. Both are rate-limited/blocked from Anthropic servers. The Kazakhstan mirror (`vkcloud.kz`) is accessible.

---

## 2. Pricing Page Technology

The pricing page is a **Next.js application** with prices embedded in the `window.__NEXT_DATA__` JSON object. Key fields:

```json
{
  "props": {
    "pageProps": {
      "staticPrices": {
        "cpu": { "perMinute": 0.145, "per30days": 6338.57 },
        "cpuHighFreq": { "perMinute": 0.228, "per30days": 9744.00 },
        "ram": { "perMinute": 0.041, "per30days": 1657.14 },
        "ssd": { "perMinute": 0.002, "per30days": 99.43 },
        "highIops": { "perMinute": 0.003, "per30days": 116.00 },
        "nvmeLowLatency": { "perMinute": 0.002, "per30days": 82.86 },
        "ipv4": { "perMinute": 0.031, "per30days": 1408.57 }
      },
      "region": "kz"
    }
  }
}
```

**No separate XHR API call is made to load prices.** The calculator is entirely client-side JavaScript using the embedded `staticPrices` object. There is no REST endpoint like `/api/pricing` or `/api/calculator`.

---

## 3. Kazakhstan Pricing (vkcloud.kz) — Extracted Data

VK Cloud uses **component-based pricing** (not pre-packaged tiers). You pay per CPU core, per GB RAM, per GB disk independently.

### Virtual Servers (Standard)

| Component | Unit | Per Minute (₸) | Per 30 Days (₸) |
|-----------|------|----------------|-----------------|
| CPU (standard) | 1 vCPU core | 0.145 | 6,338.57 |
| CPU (high-frequency) | 1 vCPU core | 0.228 | 9,744.00 |
| RAM | 1 GB | 0.041429 | 1,657.14 |
| SSD Storage | 1 GB | 0.002071 | 99.43 |
| High-IOPS Disk | 1 GB | 0.003107 | 116.00 |
| NVMe Low Latency | 1 GB | 0.002 | 82.86 |
| HDD Storage | 1 GB | ~0.000928 | 39.77 |
| External IPv4 | 1 address | 0.031 | 1,408.57 |
| Cloud Load Balancer | 1 unit | ~0.366 | 15,742.86 |

### GPU Servers (Pre-configured)

| Configuration | CPU | RAM | GPU VRAM | Per Minute (₸) | Per 30 Days (₸) |
|--------------|-----|-----|----------|----------------|-----------------|
| GPU-44-256-H200-1 | 44 vCPU | 256 GB | 141 GB (H200 x1) | 77.09 | 3,330,167.44 |
| GPU-240-2048-H200-8 | 240 vCPU | 2048 GB | 1128 GB (H200 x8) | 616.70 | 26,641,339.52 |

### Other Services

| Service | Component | Per 30 Days (₸) |
|---------|-----------|-----------------|
| Object Storage (Hotbox) | 1 GB hot data | varies |
| Object Storage (Icebox) | 1 GB cold data | lower rate |
| CDN | 1 GB transferred | 3.11 |
| Cloud Backup | per GB | varies |

**Currency note:** KZ prices are in Kazakhstani Tenge (₸). Russian prices are in Rubles (₽). The structure is identical, only currency differs.

---

## 4. Russian Pricing (Reference Values)

From third-party sources, VK Cloud Russia (₽) pricing starting points:
- Cloud Servers from **1.17 ₽/hour** (minimum configuration)
- New accounts receive **3,000 ₽** or **5,000 ₽** free credit (60-day trial)
- Legal entities: **12,000 ₽** trial credit

For exact Russian Ruble prices, the source is `https://cloud.vk.com/pricing/` — the `__NEXT_DATA__` JSON on that page contains the `staticPrices` object with `region: "ru"`.

---

## 5. OpenStack API — Machine Flavor Catalog

VK Cloud runs OpenStack. The **Nova Compute API** provides the actual list of available VM configurations ("flavors"). This is the closest thing to a pricing API for server specs.

### Authentication (Keystone v3)

**Keystone Auth URL:** `https://infra.mail.ru:35357/v3/`

**Auth Request:**
```bash
POST https://infra.mail.ru:35357/v3/auth/tokens
Content-Type: application/json

{
  "auth": {
    "identity": {
      "methods": ["password"],
      "password": {
        "user": {
          "name": "<username>",
          "password": "<password>",
          "domain": { "name": "users" }
        }
      }
    },
    "scope": {
      "project": {
        "id": "<project_id>"
      }
    }
  }
}
```

**Response:** Token returned in `X-Subject-Token` response header.

**Region:** `RegionOne` (Moscow region)

### Nova Flavors Endpoint

```
GET https://infra.mail.ru:8774/v2.1/flavors/detail
X-Auth-Token: <keystone_token>
```

**Response JSON structure:**
```json
{
  "flavors": [
    {
      "id": "flavor-uuid",
      "name": "Standard-2-8-50",
      "vcpus": 2,
      "ram": 8192,
      "disk": 50,
      "swap": 0,
      "rxtx_factor": 1.0,
      "OS-FLV-EXT-DATA:ephemeral": 0,
      "OS-FLV-DISABLED:disabled": false,
      "os-flavor-access:is_public": true,
      "extra_specs": {},
      "description": null,
      "links": [...]
    }
  ]
}
```

**Field definitions:**
| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID of flavor |
| `name` | string | Human-readable name (e.g. `Standard-2-8-50`) |
| `vcpus` | int | Number of virtual CPU cores |
| `ram` | int | RAM in **megabytes** (divide by 1024 for GB) |
| `disk` | int | Root disk in GB |
| `swap` | int | Swap disk in MB |
| `OS-FLV-EXT-DATA:ephemeral` | int | Ephemeral disk in GB |
| `OS-FLV-DISABLED:disabled` | bool | Whether flavor is disabled |
| `os-flavor-access:is_public` | bool | Public or private flavor |
| `extra_specs` | object | Additional metadata (GPU specs, etc.) |

**Note:** The flavors API returns VM specifications but NOT prices. Prices are calculated client-side from `staticPrices` (CPU/RAM/disk rates) multiplied by flavor specs.

---

## 6. Full OpenStack API Endpoint Reference

All endpoints require `X-Auth-Token: <keystone_token>` header.

| Service | Base URL | Example Endpoint |
|---------|----------|-----------------|
| Keystone (Auth) | `https://infra.mail.ru:35357/v3/` | `POST /auth/tokens` |
| Nova (Compute) | `https://infra.mail.ru:8774/v2.1/` | `GET /flavors/detail` |
| Nova (Servers) | `https://infra.mail.ru:8774/v2.1/` | `GET /servers` |
| Cinder (Block Storage) | `https://public.infra.mail.ru:8776/v3/<project_id>/` | `GET /volumes` |
| Glance (Images) | `https://infra.mail.ru:9292/v2/` | `GET /images` |
| Manila (File Shares) | `https://public.infra.mail.ru:8786/v2/<project_id>/` | `GET /shares` |
| Karboii (Backups) | `https://mcs.mail.ru/infra/karboii/v1/` | `GET /backups` |
| Cloud Logs | `https://mcs.mail.ru/cloudlogs/v1/` | `GET /logs` |

---

## 7. How to Get Prices Programmatically

### Option A: Scrape `__NEXT_DATA__` from pricing page (no auth needed)

```bash
# Fetch the Kazakhstan pricing page (accessible)
curl -s "https://vkcloud.kz/pricing/" \
  | grep -o '__NEXT_DATA__.*' \
  | head -1
```

Or use a headless browser to load `https://cloud.vk.com/pricing/` and extract `window.__NEXT_DATA__.props.pageProps.staticPrices`.

**What you get:** Per-minute rates for CPU/RAM/disk in the page's currency.

**What you don't get:** The list of available VM configurations (flavor catalog).

### Option B: OpenStack API with credentials (auth required)

```bash
# Step 1: Get token
TOKEN=$(curl -si -X POST "https://infra.mail.ru:35357/v3/auth/tokens" \
  -H "Content-Type: application/json" \
  -d '{"auth":{"identity":{"methods":["password"],"password":{"user":{"name":"USER","password":"PASS","domain":{"name":"users"}}}},"scope":{"project":{"id":"PROJECT_ID"}}}}' \
  | grep -i "x-subject-token" | awk '{print $2}')

# Step 2: List all VM flavors
curl -s "https://infra.mail.ru:8774/v2.1/flavors/detail" \
  -H "X-Auth-Token: $TOKEN" \
  | jq '.flavors[] | {name, vcpus, ram_gb: (.ram/1024), disk}'
```

**What you get:** Full flavor catalog (VM configurations) but no prices embedded.

### Option C: Combine both for full pricing data

1. Fetch `staticPrices` from `__NEXT_DATA__` (rates per unit)
2. Fetch `/flavors/detail` from Nova API (VM specs)
3. Calculate: `price = cpu_rate * vcpus + ram_rate * (ram_mb/1024) + disk_rate * disk`

---

## 8. Billing Model

- **Pay-as-you-go** with **per-second** billing precision
- Billed per component (CPU cores + RAM GB + disk GB), not per predefined tier
- Pricing starts from **~1.17 ₽/hour** for minimum server in Russia
- **Trial credit:** 3,000–5,000 ₽ (individuals) or 12,000 ₽ (legal entities)
- VAT included in displayed prices (Kazakhstan confirmed; Russia assumed same)

---

## 9. Key Findings Summary

| Question | Answer |
|----------|--------|
| Public pricing page URL | `https://cloud.vk.com/pricing/` (RU) / `https://vkcloud.kz/pricing/` (KZ, accessible) |
| Public pricing API? | **No** — no unauthenticated REST endpoint |
| XHR requests on pricing page? | **None for price data** — all prices embedded in `__NEXT_DATA__` |
| Calculator API endpoint? | **None** — calculator runs client-side JS only |
| VM configs (flavor catalog) | `GET https://infra.mail.ru:8774/v2.1/flavors/detail` (needs auth) |
| Auth mechanism | OpenStack Keystone v3 token at `https://infra.mail.ru:35357/v3/` |
| Billing unit | Per-second, per-component (CPU core, GB RAM, GB disk) |

---

## Sources

- [VK Cloud Pricing Calculator (KZ)](https://vkcloud.kz/pricing/)
- [VK Cloud Pricelist (KZ)](https://vkcloud.kz/pricelist/)
- [VK Cloud Billing Documentation](https://mcs.mail.ru/docs/ru/additionals/billing/pricing)
- [VK Cloud IaaS Tariffication](https://mcs.mail.ru/docs/base/iaas/tariffication)
- [VK Cloud API Endpoints](https://mcs.mail.ru/docs/en/manage/tools-for-using-services/rest-api/endpoints)
- [VK Cloud OpenStack CLI](https://mcs.mail.ru/docs/en/manage/tools-for-using-services/openstack-cli)
- [Deckhouse VK Cloud Installation (Keystone URL)](https://deckhouse.io/products/kubernetes-platform/gs/openstack_vk/step4.html)
- [VK Cloud GitHub Organization](https://github.com/vk-cs)
- [OpenStack Nova Flavors API Reference](https://github.com/openstack/nova/blob/master/api-ref/source/flavors.inc)
- [VK Cloud Python API Docs (dltHub)](https://dlthub.com/context/source/vk-cloud)
- [VK Cloud Review (hosting101.ru)](https://hosting101.ru/cloud.vk.com-vk-cloud)
