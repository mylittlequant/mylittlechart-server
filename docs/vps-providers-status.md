# VPS Providers — Status Report

> Date: 2026-04-05 (updated)
> Tool: dig2crawl v0.3.19 (Sonnet 4.6, gate4agent PipeSession)
> Profiles: `dig2crawl/output/<domain>/profile.json`

## Summary

- **21 providers total**: 19 tariff-table + 2 calculator-type
- **19 tariff providers ready** (validated, confidence ≥ 0.72)
- **1 calculator ready**: cloud.vk.com — staticPrices extracted from `__NEXT_DATA__`
- **1 calculator pending**: yandex.cloud — Billing API, awaiting OAuth token
- **17/21 have affiliate programs** (see `vps-affiliate-programs.md`)
- **Field schema**: `name, price, cpu, ram, disk, bandwidth` (tariff) or per-unit rates (calculator)
- **Next step**: Yandex OAuth → design daemon + DB schema → daemons write to DB

---

## Ready for Daemon — Tariff Table Providers (19)

| # | Provider | Conf | Validated | Fields | Browser | URL | Notes |
|---|----------|------|-----------|--------|---------|-----|-------|
| 1 | ihor.online | 0.93 | ✅ | 6 | no | homepage | |
| 2 | ruvds.com | 0.93 | ✅ | 5 | yes | homepage | no bandwidth field |
| 3 | the.hosting | 0.92 | ✅ | 5 | no | homepage | no bandwidth field |
| 4 | ishosting.com | 0.92 | ✅ | 6 | yes | homepage | auto-nav ×2, Cloudflare bypass |
| 5 | timeweb.cloud | 0.92 | ⚠️ | 6 | yes | homepage | L3 visual (Nuxt SPA), data OK |
| 6 | robovps.biz | 0.91 | ✅ | 6 | yes | homepage | auto-nav → /vps/ |
| 7 | serverspace.io | 0.88 | ✅ | 6 | yes | homepage | 9 records |
| 8 | adminvps.ru | 0.88 | ✅ | 5 | yes | homepage | no bandwidth field |
| 9 | ufo.hosting | 0.88 | ✅ | 6 | no | homepage | |
| 10 | omro.host | 0.87 | ✅ | 5 | no | homepage | no bandwidth field |
| 11 | selectel.ru | 0.85 | ✅ | 6 | yes | /services/cloud/servers/ | direct URL required |
| 12 | en.prohost.kg | 0.82 | ✅ | 6 | no | homepage | |
| 13 | vdsina.com | 0.82 | ✅ | 6 | no | homepage | |
| 14 | firstbyte.ru | 0.78 | ✅ | 6 | no | homepage | |
| 15 | fst.kz | 0.78 | ✅ | 6 | no | homepage | |
| 16 | hostkey.com | 0.75 | ✅ | 6 | yes | homepage | |
| 17 | fornex.com | 0.72 | ✅ | 6 | no | homepage | |
| 18 | 4dedic.io | 0.92 | ✅ | 6 | yes | /dedic/RU | 682 records, direct country URL |
| 19 | 4vps.su | 0.92 | ✅ | 6 | yes | /api/public/getTarifList | 389 records, HTML tariff table |

### Notes
- **timeweb.cloud**: L3 visual extraction found 4 records with Nuxt-hashed selectors. Data is correct.
- **4dedic.io**: Container=`div` is too broad, needs refinement to eliminate duplicates.

---

## Ready for Daemon — Calculator Providers (1)

### cloud.vk.com — ✅ SOLVED via __NEXT_DATA__

**Source**: `https://vkcloud.kz/pricing/` (Kazakhstan mirror, no geo-block)
**Method**: Extract `__NEXT_DATA__` → `props.pageProps.staticPrices`
**Currency**: KZT (Kazakhstani Tenge)
**Data model**: Per-unit monthly pricing (not fixed plans)

| Resource | Monthly price (₸) | Per-unit |
|----------|-------------------|----------|
| 1 vCPU | 6,338.57 | per core/month |
| 1 GB RAM | 1,657.14 | per GB/month |
| 1 GB SSD | 99.43 | per GB/month |
| 1 GB HDD | 39.77 | per GB/month |
| 1 GB High-IOPS | 116.00 | per GB/month |
| Floating IP | 1,408.57 | per IP/month |

Plus: 21 GPU models, 18 OS licenses, vision/voice API pricing.

**Files**: `dig2crawl/output/cloud.vk.com/static_prices.json`, `metadata.json`, `profile.json`

---

## Pending — Calculator Providers (1)

### yandex.cloud — Billing REST API (awaiting OAuth token)

**API**: `billing.api.cloud.yandex.net/billing/v1/skus?currency=RUB`
**Auth**: IAM token required (free Yandex account sufficient)
**Data model**: Per-unit pricing (core*hour, gbyte*hour)

**To obtain**:
1. User opens: `https://oauth.yandex.ru/authorize?response_type=token&client_id=1a6990aa636648e9b2ef855fa7bec2fb`
2. Logs in → gets OAuth token
3. Exchange for IAM: `POST https://iam.api.cloud.yandex.net/iam/v1/tokens {"yandexPassportOauthToken":"<TOKEN>"}`
4. Query SKUs: `GET /billing/v1/skus?currency=RUB&pageSize=1000` with `Authorization: Bearer <IAM>`

**Research**: `research-yandex-cloud-api-access.md`

---

## Affiliate Programs Summary

**17/21 providers** have affiliate/referral programs. Full details: `vps-affiliate-programs.md`

### Tier 1 (Priority)

| Provider | Max Commission | Cookie | Min Payout | Type |
|----------|---------------|--------|------------|------|
| fornex.com | 50% VPN / 40% hosting | 60 days | — | Lifetime recurring |
| vdsina.com | 50% at 1M₽/mo | 30 days | 5,000₽ | Weekly, USDT |
| timeweb.cloud | 40% hosting | 30 days | 390₽ | Also via Admitad |

### Tier 2

| Provider | Max Commission | Type |
|----------|---------------|------|
| ishosting.com | 20% VPS, crypto | Lifetime |
| adminvps.ru | 40% + 500₽/dedicated | Admitad |
| selectel.ru | 10-15% | No cookie expiry |
| hostkey.com | 10% → 5% → 2% | Multi-level, EUR |

### No program
- en.prohost.kg, 4dedic.io

### B2B only (negotiated)
- yandex.cloud (10%, 2500₽/client cap)
- cloud.vk.com (up to 35%, individual contract)

---

## Field Schema

### Tariff providers (canonical)
```json
{
  "name": "string — plan/tariff name",
  "price": "string — price (may include currency symbol, 'от' prefix)",
  "cpu": "string — CPU cores/type",
  "ram": "string — RAM amount",
  "disk": "string — disk size/type",
  "bandwidth": "string|null — network speed or traffic limit"
}
```

### Calculator providers (per-unit)
```json
{
  "cpu": { "price": 6338.57 },
  "ram": { "price": 1657.14 },
  "ssd": { "price": 99.43 },
  "hdd": { "price": 39.77 },
  "...": "additional resource types"
}
```

**4 tariff providers** missing `bandwidth`: ruvds.com, the.hosting, adminvps.ru, omro.host.

---

## Daemon Requirements (for next phase)

1. **DB schema**: providers table + vps_plans table + unit_prices table (for calculators)
2. **Two extraction modes**:
   - Tariff: `dig2crawl extract <url> --profile profile.json` → parse records → upsert
   - Calculator: fetch API/JSON → parse per-unit rates → upsert into unit_prices
3. **Schedule**: once per day (cron `0 6 * * *`)
4. **Price normalization**: strip prefixes ("от ", "From"), parse numbers, convert currencies (KZT→RUB)
5. **Change detection**: diff against previous snapshot, flag price changes
6. **Affiliate links**: store per-provider referral URL, inject into consumer API responses
7. **API for consumers**: GET /api/vps/plans, GET /api/vps/providers, GET /api/vps/cheapest, GET /api/vps/calculator-prices

---

## Research Documents

| File | Content |
|------|---------|
| `vps-affiliate-programs.md` | Affiliate programs for all 21 providers |
| `research-yandex-cloud-api-access.md` | Yandex Cloud Billing API, IAM token flow |
| `research-vk-cloud-api-access.md` | VK Cloud __NEXT_DATA__ extraction, vkcloud.kz |
| `research-yandex-cloud-pricing.md` | Initial Yandex research |
| `research-vk-cloud-pricing.md` | Initial VK Cloud research |
| `research-4dedic-4vps-api.md` | 4dedic/4vps direct URL discovery |

---

## Cookie/Profile Locations

| Provider | Browser Profile Path |
|----------|---------------------|
| yandex.cloud | `%TEMP%/yandexcloud-profile/` (manual cookie-auth) |
| All others | `%TEMP%/dig2crawl-profiles/<domain>/` (auto-created) |
