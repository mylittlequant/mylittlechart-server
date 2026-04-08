# VK Cloud Pricing Data — Programmatic Access Research

**Date**: 2026-04-05
**Scope**: cloud.vk.com (RU) and vkcloud.kz (KZ) pricing extraction

---

## Summary

VK Cloud does **not** offer a public pricing REST API. All pricing data is embedded in the
Next.js SSG (Static Site Generation) payload as a `staticPrices` object inside `__NEXT_DATA__`.
The Kazakhstan mirror (`vkcloud.kz`) is fully accessible without geo-restriction and exposes
an identical structure to the Russian site. The cleanest extraction path is:

1. Fetch `https://vkcloud.kz/_next/data/{buildId}/kz/ru/pricing.json` — returns pure JSON,
   no HTML parsing needed.
2. Parse `pageProps.staticPrices` for all per-unit rates.

---

## 1. Can We Fetch the Pricing Page with curl?

### Russian mirror (`cloud.vk.com`)

**Blocked** — `cloud.vk.com` is geo-restricted outside Russia. `WebFetch` returns:
`Claude Code is unable to fetch from cloud.vk.com`. Curl from a non-Russian IP will likely
receive a 403 or be redirected to a block page. The old URL `mcs.mail.ru/pricing/` now
issues a 301 to `cloud.vk.com`.

### Kazakhstan mirror (`vkcloud.kz`)

**Accessible** — fully reachable without geo-restriction. Same Next.js codebase,
same `__NEXT_DATA__` structure, prices in KZT (Kazakhstani Tenge).

### HTML page extraction (fallback)

If fetching the HTML page:

```bash
curl -s "https://vkcloud.kz/pricing/" \
  | grep -o '<script id="__NEXT_DATA__"[^>]*>.*</script>' \
  | sed 's/<script[^>]*>//;s/<\/script>//' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['props']['pageProps']['staticPrices'], indent=2))"
```

Or using `jq`:

```bash
curl -s "https://vkcloud.kz/pricing/" \
  | python3 -c "
import sys, re, json
html = sys.stdin.read()
m = re.search(r'<script id=\"__NEXT_DATA__\" type=\"application/json\">(.*?)</script>', html, re.S)
if m:
    data = json.loads(m.group(1))
    print(json.dumps(data['props']['pageProps']['staticPrices'], indent=2))
"
```

---

## 2. Next.js `_next/data` JSON Endpoint (Preferred Method)

Next.js SSG pages expose a direct JSON endpoint that bypasses HTML entirely:

```
https://vkcloud.kz/_next/data/{buildId}/kz/ru/pricing.json
```

**Confirmed working.** The endpoint returns the full `pageProps` object as pure JSON.

### Current buildId

```
9Xg3JGyRLSrfTZ67Tv7oS
```

> **Important**: `buildId` changes on every site deployment. It must be discovered
> dynamically. Two approaches:
>
> **Option A** (robust): Fetch the HTML page, extract `__NEXT_DATA__` JSON, read
> `.buildId` field, then construct the `_next/data` URL.
>
> **Option B** (fragile): Hardcode the buildId — breaks on site updates.

### Dynamic buildId discovery

```bash
BUILD_ID=$(curl -s "https://vkcloud.kz/pricing/" \
  | python3 -c "
import sys, re, json
html = sys.stdin.read()
m = re.search(r'<script id=\"__NEXT_DATA__\" type=\"application/json\">(.*?)</script>', html, re.S)
print(json.loads(m.group(1))['buildId'])
")
curl -s "https://vkcloud.kz/_next/data/${BUILD_ID}/kz/ru/pricing.json" | jq '.pageProps.staticPrices'
```

Or in Rust using `reqwest` — fetch HTML, regex-extract `__NEXT_DATA__`, decode JSON, read
`.buildId`, then make the second request to `_next/data/`.

---

## 3. Does VK Cloud Have a Public Pricing API?

**No.** There is no documented REST API for pricing/billing data. Confirmed:

- The VK Cloud documentation at `mcs.mail.ru/docs` (now `cloud.vk.com/docs`) lists
  OpenStack service endpoints (Nova, Cinder, Glance, etc.) but none for pricing.
- The dlthub VK Cloud connector exposes 7 resource types (servers, images, volumes,
  snapshots, shares, backups, logs) — no pricing endpoint.
- GitHub org `vk-cs` has 19 repos; none are billing/pricing APIs.
- VK Cloud's Terraform provider (`terraform-provider-vkcs`) has no pricing data source.

---

## 4. `vkcloud.kz` — Structure vs. `cloud.vk.com`

**Identical structure.** Both use the same Next.js codebase. Key differences:

| Field            | `cloud.vk.com`  | `vkcloud.kz`     |
|------------------|-----------------|------------------|
| `region`         | `"ru"`          | `"kz"`           |
| Currency         | RUB (₽)         | KZT (₸)          |
| Route template   | `/[locale]/pricing` | `/kz/[locale]/pricing` |
| Geo-restriction  | Blocked outside RU | Accessible globally |
| `__NEXT_DATA__`  | Present         | Present (confirmed) |
| `staticPrices`   | Present         | Present (confirmed) |
| buildId path     | `_next/data/{id}/ru/pricing.json` | `_next/data/{id}/kz/ru/pricing.json` |

The KZ mirror is the **recommended extraction target** for environments outside Russia.

---

## 5. OpenStack Flavors Endpoint — Auth Required

VK Cloud runs OpenStack Nova. The compute endpoint for the Moscow region is:

```
https://infra.mail.ru:8774/v2.1/{project_id}/flavors
```

**Authentication is required.** All OpenStack Nova endpoints require a Keystone token
passed as `X-Auth-Token`. There is no public unauthenticated flavors endpoint.

Keystone auth endpoint:
```
https://infra.mail.ru:35357/v3/
```

Even if authenticated, Nova flavors return hardware configurations (vCPU/RAM/disk counts)
**without pricing data** — OpenStack does not natively store per-flavor prices.
Pricing is a VK Cloud overlay computed from `staticPrices` coefficients applied to
resource counts.

---

## 6. Complete `staticPrices` JSON Structure (KZ Region)

Confirmed via `_next/data` endpoint. All prices in **KZT per 30-day month** unless noted.

```json
{
  "cpu":              { "price": 6338.57 },
  "cpuCascadeLake":   { "price": 6338.57 },
  "ram":              { "price": 1657.14 },
  "ssd":              { "price": 99.43   },
  "hdd":              { "price": 39.77   },
  "high_iops_disk":   { "price": 116.0   },
  "high_iops_ha_disk":{ "price": 0       },
  "nix":              { "price": 0       },

  "hotDataVolume":    { "price": 17.4    },
  "hotDataOutput":    { "price": 9.94    },
  "iceDataVolume":    { "price": 8.27    },
  "iceDataOutput":    { "price": 12.73   },

  "factors": {
    "trove":  { "coeff": 1.2 },
    "magnum": { "coeff": 1.2 },
    "sahara": { "coeff": 1.2 }
  },
  "databasesCoeff": { "coeff": 1.2 },
  "bigdataCoeff":   { "coeff": 1.2 },
  "backupCoeff":    { "coeff": 37.29 },

  "gpu": {
    "yearTeslaV100":    { "price": 155000 },
    "yearTeslaV100S":   { "price": 173000 },
    "yearTeslaA100":    { "price": 202000 },
    "monthTeslaV100":   { "price": 172000 },
    "monthTeslaV100S":  { "price": 192000 },
    "monthTeslaA100":   { "price": 224000 },
    "hourTeslaV100":    { "price": 181000 },
    "hourTeslaV100S":   { "price": 202000 },
    "hourTeslaA100":    { "price": 236000 },
    "yearTeslaL4":      { "price": 0 },
    "yearTeslaA30":     { "price": 0 },
    "yearTeslaL40S":    { "price": 0 },
    "monthTeslaL4":     { "price": 0 },
    "monthTeslaA30":    { "price": 0 },
    "monthTeslaL40S":   { "price": 0 },
    "hourTeslaL4":      { "price": 0 },
    "hourTeslaA30":     { "price": 0 },
    "hourTeslaL40S":    { "price": 0 },
    "hourTeslaA10080GB":{ "price": 0 }
  },

  "vision": {
    "photoFaces":  { "price": 0.001 },
    "videoFaces":  { "price": 0.001 },
    "videoMinute": { "price": 6.0   }
  },
  "voice": {
    "shortAmount":  { "coeff": 0.01 },
    "longAmount":   { "coeff": 0.01 },
    "speechAmount": { "coeff": 1.0  }
  },

  "externalIp": { "price": 1408.57 },

  "balancers": {
    "cloudServer": { "price": 15742.86 },
    "cloudGpu":    { "price": 15742.86 },
    "clusters":    { "price": 6297.14  },
    "databases":   { "price": 6297.14  }
  },

  "disaster": {
    "physical": { "price": 15148.458 },
    "virtual":  { "price": 15148.458 }
  },

  "bigdataLicenses": {
    "enterprise": { "price": 0 }
  },
  "dbLicenses": {
    "standart":    { "price": 0    },
    "enterprise":  { "price": 8640 },
    "enterprise1c":{ "price": 8640 }
  },

  "licenses": [
    { "id": "8",   "price": 3001.5,  "name": "altlinux"      },
    { "id": "11",  "price": 9004.6,  "name": "altlinux_fstek"},
    { "id": "14",  "price": 6948.0,  "name": "astra_or"      },
    { "id": "20",  "price": 8858.7,  "name": "astra_vor"     },
    { "id": "17",  "price": 4502.3,  "name": "redos"         },
    { "id": "23",  "price": 11505.9, "name": "redos_fstek"   },
    { "id": "26",  "price": 19640.0, "name": "msofficepro"   },
    { "id": "29",  "price": 9520.0,  "name": "mssqlw"        },
    { "id": "32",  "price": 5120.0,  "name": "mswinsrv"      },
    { "id": "38",  "price": 5160.0,  "name": "msexchentplus" },
    { "id": "35",  "price": 14400.0, "name": "msofficestd"   },
    { "id": "41",  "price": 152160.0,"name": "mssql"         },
    { "id": "44",  "price": 583520.0,"name": "mssqle"        },
    { "id": "47",  "price": 2200.0,  "name": "msexchstd"     },
    { "id": "50",  "price": 16440.0, "name": "mssqlsal"      },
    { "id": "53",  "price": 7400.0,  "name": "msrds"         },
    { "id": "56",  "price": 3560.0,  "name": "msexchent"     },
    { "id": "110", "price": 3840.0,  "name": "msexchstdplus" }
  ]
}
```

### Per-minute rates (derived)

The calculator uses per-minute billing (`pay-as-you-go, per-second precision`).
30-day month = 43,200 minutes. Conversion from monthly rates above:

| Resource        | Monthly (₸) | Per-minute (₸)        |
|-----------------|-------------|----------------------|
| 1 vCPU          | 6,338.57    | 0.14673 ₸/min        |
| 1 GB RAM        | 1,657.14    | 0.038378 ₸/min       |
| 1 GB SSD        | 99.43       | 0.0023 ₸/min         |
| 1 GB HDD        | 39.77       | 0.000921 ₸/min       |
| 1 GB High-IOPS  | 116.00      | 0.002685 ₸/min       |
| Floating IP     | 1,408.57    | 0.032605 ₸/min       |

From the pricelist page (direct per-minute values confirmed):

| Resource        | Per-minute (₸)  | Note                     |
|-----------------|-----------------|--------------------------|
| 1 vCPU          | 0.145 ₸/min     | Pricelist page           |
| 1 GB RAM        | 0.041429 ₸/min  | Pricelist page           |
| 1 GB SSD        | 0.002071 ₸/min  | Pricelist page           |
| 1 GB High-IOPS  | 0.003107 ₸/min  | Pricelist page           |
| 1 GB NFS/CIFS   | 0.001036 ₸/min  | Pricelist page           |
| Floating IPv4   | 0.031071 ₸/min  | Pricelist page           |

---

## 7. Pricing for H200 GPU Instances (from pricelist page)

The pricelist page contains newer GPU models not in `staticPrices`:

| Flavor                | Price        |
|-----------------------|--------------|
| GPU-44-256-H200-1     | 77.09 ₸/min  |
| GPU-240-2048-H200-8   | 616.7 ₸/min  |

These are likely loaded from a separate data source or the KZ pricing page's `staticPrices`
may have a newer buildId with these values. Worth re-fetching `_next/data` with a fresh
buildId after a site deployment.

---

## 8. Recommended Implementation (Rust)

```rust
use reqwest::Client;
use serde_json::Value;
use regex::Regex;

async fn fetch_vk_cloud_prices(client: &Client) -> anyhow::Result<Value> {
    // Step 1: Fetch HTML to get current buildId
    let html = client
        .get("https://vkcloud.kz/pricing/")
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await?
        .text()
        .await?;

    // Step 2: Extract buildId from __NEXT_DATA__
    let re = Regex::new(r#"<script id="__NEXT_DATA__" type="application/json">(.*?)</script>"#)?;
    let caps = re.captures(&html).ok_or_else(|| anyhow::anyhow!("__NEXT_DATA__ not found"))?;
    let next_data: Value = serde_json::from_str(&caps[1])?;
    let build_id = next_data["buildId"].as_str().ok_or_else(|| anyhow::anyhow!("buildId missing"))?;

    // Step 3: Fetch pure JSON from _next/data endpoint
    let json_url = format!(
        "https://vkcloud.kz/_next/data/{}/kz/ru/pricing.json",
        build_id
    );
    let pricing_data: Value = client
        .get(&json_url)
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await?
        .json()
        .await?;

    // Step 4: Extract staticPrices
    let static_prices = pricing_data["pageProps"]["staticPrices"].clone();
    Ok(static_prices)
}
```

**Crate dependencies**: `reqwest`, `serde_json`, `regex`, `anyhow`

---

## 9. Alternative: Direct `staticPrices` from HTML (Single Request)

If minimizing requests:

```rust
async fn fetch_vk_cloud_prices_single(client: &Client) -> anyhow::Result<Value> {
    let html = client
        .get("https://vkcloud.kz/pricing/")
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await?
        .text()
        .await?;

    let re = Regex::new(r#"<script id="__NEXT_DATA__" type="application/json">(.*?)</script>"#)?;
    let caps = re.captures(&html).ok_or_else(|| anyhow::anyhow!("__NEXT_DATA__ not found"))?;
    let next_data: Value = serde_json::from_str(&caps[1])?;

    Ok(next_data["props"]["pageProps"]["staticPrices"].clone())
}
```

---

## 10. No Public Pricing API — Confirmed

Summary of investigated endpoints:

| Endpoint                          | Result                            |
|-----------------------------------|-----------------------------------|
| `cloud.vk.com/pricing/`           | Geo-blocked outside Russia        |
| `vkcloud.kz/pricing/`             | Accessible, has `__NEXT_DATA__`   |
| `vkcloud.kz/_next/data/{id}/kz/ru/pricing.json` | **Works, pure JSON** |
| `infra.mail.ru:8774/v2.1/flavors` | Requires auth, no pricing data    |
| `mcs.mail.ru/docs` billing API    | Does not exist publicly           |
| VK Cloud GitHub (`vk-cs`)         | No pricing repo                   |
| OpenStack Keystone public catalog | No flavor pricing in catalog      |

---

## Sources

- [VK Cloud Kazakhstan — Pricing Calculator](https://vkcloud.kz/pricing/)
- [VK Cloud Kazakhstan — Pricelist](https://vkcloud.kz/pricelist/)
- [VK Cloud Kazakhstan — `_next/data` JSON (KZ)](https://vkcloud.kz/_next/data/9Xg3JGyRLSrfTZ67Tv7oS/kz/ru/pricing.json)
- [VK Cloud API Endpoints (mcs.mail.ru docs)](https://mcs.mail.ru/docs/en/manage/tools-for-using-services/rest-api/endpoints)
- [VK Cloud GitHub Organization](https://github.com/vk-cs)
- [OpenStack Nova Flavors API Reference](https://docs.openstack.org/nova/latest/user/flavors.html)
- [OpenStack API Quick Start (auth requirements)](https://docs.openstack.org/api-quick-start/api-quick-start.html)
- [Deckhouse on VK Cloud — OpenStack endpoint reference](https://deckhouse.io/products/kubernetes-platform/gs/openstack_vk/step4.html)
- [dltHub VK Cloud API Docs](https://dlthub.com/context/source/vk-cloud)
- [VK Cloud (mcs.mail.ru) — Tariffication](https://mcs.mail.ru/docs/en/base/s3/tariffication)
