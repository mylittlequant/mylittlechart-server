# Partner/Affiliate API Research: VPS Hosting Providers

**Compiled:** 2026-04-06
**Purpose:** Evaluate programmatic API availability for pricing catalogs, referral link generation, and affiliate stats — to replace web scraping with official integrations.

---

## Summary Table

| Provider | Has API? | Pricing Catalog API | Affiliate API | Referral Link API | Auth Method | Notes |
|---|---|---|---|---|---|---|
| **fornex.com** | Partial | No (web scraping only) | No (dashboard only) | No | Api-Key header | Only DNS API documented publicly |
| **vdsina.com** | Yes (full REST) | Yes (`GET /v1/server-plan`) | Unclear (not documented) | No | Token (HTTP header) | Full public API with PDF docs |
| **timeweb.cloud** | Yes (full REST) | Yes (`GET /api/v1/presets/servers`) | No (dashboard only) | No | JWT Bearer | Full API; reseller API integration exists |
| **ishosting.com** | Yes (REST) | Unclear | No | No | API Key (Client Area) | API covers orders/billing, not clear on catalog |
| **adminvps.ru** | No (via Admitad) | No | Via Admitad API | Via Admitad deeplink | Admitad Bearer | Campaign ID: 21749; use Admitad API |
| **selectel.ru** | Yes (full REST) | Partial (pricing docs) | No API (dashboard only) | No | Token | 13 API categories; no affiliate API |
| **ruvds.com** | Yes (REST) | Unclear | No (dashboard only) | No | Token | White label API mentioned; details sparse |
| **hostkey.com** | Yes (full REST) | Unclear | Via affiliate program | No | API Key + session | Full Invapi; WHMCS module available |
| **serverspace.io** | Yes (REST) | Unclear | Dashboard only | No | API Key | Full infrastructure API; no partner API |

---

## ADMITAD PLATFORM (Covers: adminvps.ru, timeweb.com, ruvds.com)

This is the highest-value finding. Three of the providers are on the Admitad affiliate network, which has a **full programmatic API** for deeplink generation with sub-IDs.

### Admitad Publisher API

**Base URL:** `https://api.admitad.com/`
**Authentication:** OAuth 2.0 Bearer token
**Documentation:** https://developers.admitad.com/knowledge-base/

### Deeplink Generator Endpoint

```
GET https://api.admitad.com/deeplink/{w_id}/advcampaign/{c_id}/
```

**Parameters:**
| Parameter | Type | Required | Description |
|---|---|---|---|
| `w_id` | string | Yes | Your publisher/webmaster ID |
| `c_id` | string | Yes | Advertiser campaign ID |
| `ulp` | string | Yes | Target URL (URL-encoded), up to 200 URLs |
| `subid` | string | No | Sub-ID tracking tag (50 char max) |
| `subid1` | string | No | Sub-ID level 1 (50 char max) |
| `subid2` | string | No | Sub-ID level 2 (50 char max) |
| `subid3` | string | No | Sub-ID level 3 (50 char max) |
| `subid4` | string | No | Sub-ID level 4 (120 char max) |

**Required access right:** `deeplink_generator`

**Example Request:**
```bash
curl -L \
  -H 'Authorization: Bearer <access_token>' \
  -X GET \
  'https://api.admitad.com/deeplink/232236/advcampaign/21749/?subid=vps_ru&subid1=adminvps&ulp=https%3A%2F%2Fadminvps.ru%2F'
```

**Response:**
```json
[
  {
    "link": "https://ad.admitad.com/g/...",
    "is_affiliate_product": null
  }
]
```

### Affiliate Programs List Endpoint

```
GET https://api.admitad.com/advcampaigns/
```

Use this to find campaign IDs for providers on Admitad.

**Documentation:** https://developers.admitad.com/knowledge-base/article/affiliate-programs_1

### Admitad Campaign IDs (Known)

| Provider | Admitad Campaign ID | Notes |
|---|---|---|
| **adminvps.ru** | `21749` | Confirmed — EPC 127₽, 0.6% CR, 88.6% approval |
| **timeweb.com** | Unknown — query via API | Check `GET /advcampaigns/` |
| **ruvds.com** | Unknown — query via API | Check `GET /advcampaigns/` |

### Sub-ID Strategy

Sub-IDs enable granular tracking. Recommended mapping:
- `subid` = provider slug (e.g., `adminvps`, `timeweb`)
- `subid1` = campaign/placement ID
- `subid2` = context (e.g., `vps_ru_2core`)
- `subid3` = user segment or A/B test variant
- `subid4` = full context string (120 chars available)

---

## 1. FORNEX.COM

**Our affiliate code:** `ft1f1e`
**Program URL:** https://fornex.com/help/partner-program/

### Partner API Status: NONE (partial)

Fornex has a **DNS management API** but no documented affiliate/partner API and no pricing catalog API.

### Known API

**Base URL:** `https://fornex.com/api/dns/v0.1`
**Authentication:** `Authorization: Api-Key <your_api_key>` header
**Source:** https://github.com/acmesh-official/acme.sh/pull/5162

#### DNS Endpoints (only documented API)

| Endpoint | Method | Description |
|---|---|---|
| `/{domain}/entry_set/` | GET | List all DNS records |
| `/{domain}/entry_set/` | POST | Add DNS record |
| `/{domain}/entry_set/{record_id}/` | DELETE | Delete DNS record |

### Affiliate Program Details

- **Commission:** Up to 50% of every payment, forever (rate scales with referral's active orders)
- **Cookie duration:** 60 days
- **Referral link:** Dashboard-generated; can target any page on fornex.com
- **Custom links:** "Create link" tool — enter any URL to create a tracking link
- **Payout:** Within 10 days after referral payment clears
- **Withdrawal:** USDT (TRC-20) for regular amounts; wire/PayPal for agencies >€1,000/month

### Pricing Catalog

No API. VPS rates page: https://fornex.com/help/vps-packages/
Scraping target: `https://fornex.com/virtual-private-servers/`

### Conclusion

**Scraping required** for pricing. No affiliate API. Monitor for API expansion.

---

## 2. VDSINA.COM / VDSINA.RU

**Our partner code:** `partner=829m84wp4n8h`
**API docs:** https://vdsina.ru/tech/api | https://www.vdsina.com/tech/api
**PDF docs:** https://vdsina.ru/files/docs/public_api.pdf

### Partner API Status: FULL PUBLIC API (pricing), PARTNER STATS UNCLEAR

VDSina has the best-documented public API among Russian providers.

### API Overview

**Base URL:** `https://api.vdsina.ru/` (inferred) or via `vdsina.com`
**Authentication:** Token in HTTP `Authorization` header
**Data format:** JSON
**Methods:** GET, POST, PUT, DELETE

### Key Pricing Endpoint

```
GET /v1/server-plan/{ID}
```

Returns list of tariff plans for a server-plan-group ID.

**Response fields:**
| Field | Type | Description |
|---|---|---|
| `active` | bool | Whether plan is orderable |
| `enable` | bool | Whether plan is enabled |
| `cost` | decimal | Price for the period (usually 1 day) |
| `period` | string | Billing period |
| `min_money` | decimal | Minimum balance required to order |
| `can_bonus` | bool | Whether bonus funds apply |
| `data` | object | Full specs (CPU, RAM, disk, etc.) |

### Additional API Capabilities

Based on public docs and Terraform provider (https://github.com/scinfra-pro/terraform-provider-vdsina):
- Server lifecycle management (create, start, stop, delete)
- Server plan listing
- OS/image listing
- Account balance queries
- IP management

### Partner API

**Not documented publicly.** The partner/referral statistics are available in the control panel under "Партнёрка" menu. No API endpoints for affiliate stats found.

**Partner program terms:**
- 20% from referred client expenses OR
- 10% from expenses + 10% discount to the referred client
- Credits once per week

### Conclusion

**Use the public API for pricing catalog** — `GET /v1/server-plan/{ID}` gives full tariff data.
**Partner stats:** Dashboard only, no API. Use scraping or manual export.

---

## 3. TIMEWEB.CLOUD / TIMEWEB.COM

**Our partner code:** `i=140853`
**API docs:** https://timeweb.cloud/api-docs
**Alt docs:** https://agent.timeweb.cloud/docs

### Partner API Status: FULL PUBLIC API (pricing + infrastructure), RESELLER API INTEGRATION EXISTS

Timeweb Cloud has the most complete API among all providers researched.

### API Overview

**Base URL:** `https://api.timeweb.cloud`
**Authentication:** JWT Bearer token (generated in control panel → API and Terraform section)
**Rate limit:** 20 requests/second per endpoint (HTTP 429 if exceeded)
**SDKs:** Python, PHP, Go (on GitHub: https://github.com/timeweb-cloud)

### Pricing Catalog Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/v1/presets/servers` | GET | List all VPS server presets with specs and pricing |
| `GET /api/v1/presets/storages` | GET | List storage pricing |
| `GET /api/v1/account/services/cost` | GET | Cost of all active services on account |

The `/api/v1/presets/servers` endpoint returns full VPS plan catalog including CPU count, RAM, disk size, and monthly price.

### Partner/Reseller Programs

**Agent Program (our affiliate link with `i=140853`):**
- 10%+ commission per client payment, scales with volume
- Paid next business day on request
- No dedicated affiliate API — dashboard only

**Reseller Program:**
- Progressive discounts: 20% → 45% based on monthly revenue
- **Explicit "API Integration" mentioned** for reseller automation
- Contact: d.borisova@timeweb.ru for reseller API access
- Discount tiers:

| Monthly Revenue | Discount |
|---|---|
| Start | 20% |
| ₽20K–50K | 25% |
| ₽50K–100K | 30% |
| ₽100K–500K | 35% |
| ₽500K–1.5M | 40% |
| >₽1.5M | 45% |

**Timeweb (classic, `timeweb.com`) — separate partner program:**
- "Вебмастер" (Webmaster) program documented at https://timeweb.com/ru/docs/partnerskie-programmy/programma-webmaster/
- Also on Admitad — find campaign ID via `GET https://api.admitad.com/advcampaigns/?query=timeweb`

### Terraform Provider

Full Terraform provider available: https://registry.terraform.io/providers/timeweb-cloud/timeweb-cloud/latest/docs
Useful for understanding all available API resources and their fields.

### Conclusion

**Best-in-class API** for pricing catalog. Use `GET /api/v1/presets/servers` for full VPS catalog.
**Reseller integration via API** is available — contact sales for credentials.
**Affiliate stats:** Dashboard only for agent program. Reseller may have API access.

---

## 4. ISHOSTING.COM

**Our affiliate code:** `NzI5MSM2`
**API docs:** https://help.ishosting.com/en/ishosting-api
**API endpoint:** https://api.ishosting.com
**Affiliate program:** https://ishosting.com/en/affiliate-program

### Partner API Status: PUBLIC API EXISTS, AFFILIATE NOT INTEGRATED

### API Overview

**Base URL:** `https://api.ishosting.com`
**Authentication:** API Key (generated in Client Area)
**Documentation:** https://help.ishosting.com/en/ishosting-api

### API Capabilities

The API covers:
- Order creation
- Invoice payment
- Service status checking
- Service management

**Note:** The API appears focused on infrastructure management, not pricing catalog retrieval or affiliate program integration.

### Affiliate Program Details

- **Commission:** Up to 50% on first purchase (most expensive item in cart)
- **Ongoing:** Up to 20% on VPS/VPN/storage recurring; up to 15% on dedicated servers
- **Minimum withdrawal:** $20 USD
- **Payout methods:** Cryptocurrency supported + traditional methods

### Conclusion

**API exists** but covers orders/billing, not pricing catalog or affiliate stats.
**Affiliate stats:** Dashboard only.
For pricing: scrape https://ishosting.com/en/vps or contact for reseller pricing API.

---

## 5. ADMINVPS.RU

**Our affiliate code:** `aff=30413`
**Admitad campaign ID:** `21749`
**Partner page:** https://adminvps.ru/about/partners.php
**Admitad offer page:** https://www.admitad.ru/store/offers/adminvps/

### Partner API Status: VIA ADMITAD API (see Admitad section above)

AdminVPS has no proprietary affiliate API. All affiliate integration goes through **Admitad**.

### Affiliate via Admitad

Use the Admitad deeplink API to generate referral links with sub-IDs:

```bash
# Generate tracked link to adminvps.ru
curl -H 'Authorization: Bearer <admitad_token>' \
  'https://api.admitad.com/deeplink/{w_id}/advcampaign/21749/?subid=adminvps&ulp=https%3A%2F%2Fadminvps.ru%2F'
```

**Admitad campaign stats:**
- EPC: 127 ₽
- Conversion Rate: 0.6%
- Approval Rate: 88.6%
- Processing Time: ~39 days
- Verification: Monthly (1st–14th), manual

### Reseller Program

Listed as "Coming Soon" on their website. Not yet available.

### Partner Program (direct)

- **Commission:** Up to 40% of client payments (30% for hosting/VPS + 500₽ per dedicated server)
- **Direct affiliate link format:** `https://adminvps.ru/?aff=<YOUR_ID>`
- **Minimum payout:** ₽1,000
- **Materials:** 8,000+ partners, ₽45M+ distributed

### Conclusion

**Use Admitad API** with campaign ID `21749` for programmatic deeplinks.
**No standalone affiliate API.** AdminVPS direct links use `?aff=30413` parameter.

---

## 6. SELECTEL.RU

**No account yet**
**API docs:** https://docs.selectel.ru/en/api/
**Affiliate docs:** https://docs.selectel.ru/en/partner-program/

### Partner API Status: NO AFFILIATE API

### API Overview

**Base URL:** Multiple (per product)
**Authentication:** Token-based (Keystone-style, per docs)
**Documentation:** https://docs.selectel.ru/en/api/

Selectel has an extensive **infrastructure API** (26+ product APIs), but **no partner/affiliate API**.

### API Categories

1. Authorization and URLs
2. Users and Roles (IAM, Federations)
3. Balance and Consumption (billing/stats/reports)
4. Dedicated Servers
5. Cloud Platform (projects, databases, Kubernetes, DNS registries)
6. Secrets Manager
7. Certificates Manager
8. S3 and Object Storage
9. Network Services (routing, email, DNS, IP)
10. Logging (Audit Logs)
11. VMware
12. Cloud for 1C
13. Tickets and Support

### Affiliate Program Details

- **Commission tiers:**
  - 9% flat (referrals before Sep 1, 2023)
  - 10% for referrals spending ≤₽1,000,000/month
  - 15% for referrals spending >₽1,000,000/month
- **Payment:** By 15th of following month
- **Referral link:** Available in control panel (account menu → Affiliate Program → Overview)
- **Attachment period:** Unlimited once registered via link
- **Can add referrals manually:** Within 7 days of their registration

### Pricing

Docs: https://docs.selectel.ru/en/cloud-servers/about/payment/
VDS pricing: https://vds.selectel.ru/en/pricing.html
Sample rates: 200₽–3200₽/month for cloud servers

### Conclusion

**No affiliate API.** Dashboard-only partner management.
**Infrastructure API** is full-featured for cloud management.
**For pricing:** Use documentation pages or contact for reseller/partner pricing API.

---

## 7. RUVDS.COM

**No account yet**
**API docs:** https://ruvds.com/en-usd/use_api
**Partner page:** https://ruvds.com/en-usd/partner

### Partner API Status: INFRASTRUCTURE API EXISTS, AFFILIATE API UNCLEAR

### API Overview

**Authentication:** Token-based
**Documentation:** https://ruvds.com/en-usd/use_api
**White Label:** Explicitly mentioned — "create your own White Label business using full spectrum of API functions"

RUVDS promotes a **White Label API** for building your own VPS hosting reseller business.

### Affiliate/Partner Program

**Commission tiers:**
| Active Servers / Earnings | Commission |
|---|---|
| Starting | 15% |
| 30+ servers / ₽20K+ earned | 20% |
| 60+ servers / ₽40K+ earned | 25% |

**Important details:**
- Commission on all client expenses for 1 year from registration
- Promo codes: custom partner codes, discount comes from your commission
- Minimum withdrawal: ₽5,000 (card), ₽1,000 (SBP)
- Monthly cap: ₽50,000 withdrawal, ₽100,000 accrual
- Card withdrawal fee: 10%

**Access:** Account Settings → Partner Program → Enable Partner Account

**On Admitad too:** RUVDS appears on Admitad — find campaign ID via API:
```bash
GET https://api.admitad.com/advcampaigns/?query=ruvds
```

### Conclusion

**Use Admitad API** for deeplink generation if RUVDS is on Admitad.
**White Label API** available for full reseller business — needs direct contact for access.
**No documented affiliate stats API.** Dashboard only.

---

## 8. HOSTKEY.COM

**No account yet**
**API docs:** https://hostkey.com/documentation/apidocs/api/
**Reseller docs:** https://hostkey.com/documentation/resellers/
**Invapi page:** https://hostkey.com/about-us/invapi/

### Partner API Status: FULL RESELLER API + WHMCS MODULE

HOSTKEY has the most mature **reseller infrastructure** of all providers researched.

### API Overview

**Base URL:** `https://api.hostkey.com/v1/billing/`
**Authentication:**
1. Obtain API key in Invapi (control panel)
2. Call `auth/login` with API key → get session token
3. Use session token for subsequent requests
4. Alternative: `auth/whmcslogin` with login/password

### API Endpoint Categories

| Category | Endpoints |
|---|---|
| Authentication | `auth/login`, `auth/whmcslogin`, `api_keys/add` |
| Billing | Account management, payments |
| Instant Servers | Order, manage instant (VPS) servers |
| Stock Servers | Order, manage dedicated servers |
| Remote Access | IPMI/DRAC, console access |
| Virtual Servers | VPS lifecycle management |
| Server Control | Power (reboot/on/off), OS reinstall |
| Network Operations | NICs, IP blocking, DNS |
| Remote Hands | Support requests |
| Server Tags | Tagging and organization |
| VM Snapshots | Snapshot management |
| Asynchronous Actions | Task tracking |

### Server Catalog Endpoint

```
GET /eq.php?action=show
```

Returns server information including hardware details, billing data, and configuration. Used for server listings.

### Reseller Program

- **Discounts:** Up to 20% wholesale
- **WHMCS Module:** Full reseller module (WHMCS 8.8+)
  - GitHub: https://github.com/hkadm/HostkeyResellerMod
  - WHMCS Marketplace: https://marketplace.whmcs.com/product/7340
- **White label:** Own branding, own domain for control panel
- **Pricing:** Resellers set own prices (cannot go below HOSTKEY prices)

### Affiliate Program

- Commission: Up to 10% on referred customer orders, for the customer's lifetime
- Minimum: 3 confirmed conversions from different clients required
- Marketing materials + branded links provided

### Conclusion

**Best reseller API** — full WHMCS integration, white label, comprehensive endpoint coverage.
**For pricing catalog:** Use Invapi API (`/eq.php?action=show`) after auth.
**Affiliate:** Basic 10% commission, no dedicated affiliate API.

---

## 9. SERVERSPACE.IO

**No account yet**
**API docs:** https://serverspace.io/services/api/ | https://docs.serverspace.io/public_api.html
**Partner page:** https://serverspace.io/partnership/

### Partner API Status: INFRASTRUCTURE API EXISTS, NO AFFILIATE API

### API Overview

**Base URL:** Referenced at `https://docs.serverspace.io/public_api.html`
**Authentication:** API Key generated in control panel → Automation → API tab
- Keys support expiration dates
- Keys support IP address restrictions
**Data format:** JSON
**Methods:** GET, DELETE, POST, PUT

### API Capabilities

- Deploy and manage virtual servers
- Change server configurations
- Create and manage networks and network interfaces
- Create and manage snapshots
- Manage additional disk volumes
- Manage DNS records
- Access project info and current balance
- Retrieve task information, server metadata, SSH keys

"Serverspace Public API allows users to perform almost all actions available through control panel."

### Referral/Partner Program

- **Commission:** 10% for year 1, 5% thereafter (ongoing while referral pays)
- **Referral bonus:** Referred clients get +20% on first payment
- **Tools:** Referral link (unique URL), banners, embeddable calculator widget
- **No programmatic API** for referral link generation
- **White label:** Available — see https://serverspace.io/partnership/

### Conclusion

**Infrastructure API** is full-featured but no public pricing catalog endpoint documented.
**No affiliate API.** Dashboard-only partner management.
Contact for white label/reseller API access.

---

## Integration Recommendations

### Priority 1: Use Admitad API (Immediate — covers 3 providers)

For **adminvps.ru**, **timeweb.com**, and **ruvds.com** (verify on Admitad):

```rust
// Admitad deeplink generation
// GET https://api.admitad.com/deeplink/{w_id}/advcampaign/{c_id}/
// Header: Authorization: Bearer <admitad_bearer_token>
// Params: ulp=<target_url>&subid=<tracking_id>
```

Steps:
1. Get Admitad publisher credentials (w_id + Bearer token)
2. Find campaign IDs: `GET /advcampaigns/?query=adminvps` (21749 confirmed), timeweb, ruvds
3. Use `subid` through `subid4` for sub-tracking
4. Store campaign IDs in config

### Priority 2: VDSina Public API (Pricing Catalog)

```
GET https://api.vdsina.ru/v1/server-plan/{group_id}
Authorization: <token>
```

Gives full tariff data. Needs API token from VDSina account.

### Priority 3: Timeweb Cloud API (Pricing Catalog)

```
GET https://api.timeweb.cloud/api/v1/presets/servers
Authorization: Bearer <jwt_token>
```

Returns full VPS preset catalog with specs and prices. Best-documented pricing API.

### Priority 4: Web Scraping (Fallback for others)

For providers without pricing APIs:
- **Fornex:** `https://fornex.com/help/vps-packages/`
- **ishosting.com:** `https://ishosting.com/en/vps`
- **Selectel:** `https://vds.selectel.ru/en/pricing.html`
- **RUVDS:** `https://ruvds.com/en-usd/vps`
- **Serverspace:** `https://serverspace.io/pricing/`
- **Hostkey:** `https://hostkey.com/vps/`

### Priority 5: Contact for Reseller APIs

Both **Timeweb Cloud** (d.borisova@timeweb.ru) and **RUVDS** (White Label) mention reseller API integration. These would give pricing at partner discount levels plus automation capabilities.

---

## Referral Link Format Reference

For direct (non-Admitad) links where we have accounts:

| Provider | Link Format | Our Code |
|---|---|---|
| fornex.com | Generated in dashboard (custom URL builder) | `ft1f1e` |
| vdsina.com | `https://vdsina.com/?partner=829m84wp4n8h` | `829m84wp4n8h` |
| timeweb.cloud | `https://timeweb.cloud/?i=140853` | `140853` |
| ishosting.com | Dashboard-generated with code `NzI5MSM2` | `NzI5MSM2` |
| adminvps.ru | `https://adminvps.ru/?aff=30413` OR via Admitad | `30413` |

---

## Sources

- [Fornex Affiliate Program](https://fornex.com/help/partner-program/)
- [Fornex API (acme.sh PR)](https://github.com/acmesh-official/acme.sh/pull/5162)
- [VDSina Public API](https://www.vdsina.com/tech/api)
- [VDSina API PDF](https://vdsina.ru/files/docs/public_api.pdf)
- [VDSina Terraform Provider](https://github.com/scinfra-pro/terraform-provider-vdsina)
- [Timeweb Cloud API Docs](https://timeweb.cloud/api-docs)
- [Timeweb Cloud Partner Program](https://timeweb.cloud/partners)
- [Timeweb Cloud Reseller Program](https://timeweb.cloud/partners/reseller)
- [Timeweb Cloud SDK Python](https://github.com/timeweb-cloud/sdk-python)
- [ishosting.com API](https://help.ishosting.com/en/ishosting-api)
- [ishosting.com Affiliate Program](https://ishosting.com/en/affiliate-program)
- [AdminVPS Partner Program](https://adminvps.ru/about/partners.php)
- [AdminVPS on Admitad](https://www.admitad.ru/store/offers/adminvps/)
- [Admitad Deeplink Generator API](https://developers.admitad.com/knowledge-base/article/deeplink-generator_1)
- [Admitad Publisher API](https://developers.admitad.com/knowledge-base/article/affiliate-programs_1)
- [Selectel API Documentation](https://docs.selectel.ru/en/api/)
- [Selectel Affiliate Program](https://docs.selectel.ru/en/partner-program/about-partner-program/)
- [RUVDS API Features](https://ruvds.com/en-usd/use_api)
- [RUVDS Partner Program](https://ruvds.com/en-usd/partner)
- [HOSTKEY API Documentation](https://hostkey.com/documentation/apidocs/api/)
- [HOSTKEY Reseller Program](https://hostkey.com/about-us/reseller-program/)
- [HOSTKEY Invapi](https://hostkey.com/about-us/invapi/)
- [HOSTKEY WHMCS Module GitHub](https://github.com/hkadm/HostkeyResellerMod)
- [Serverspace Cloud API](https://serverspace.io/services/api/)
- [Serverspace Referral Program](https://serverspace.io/partnership/referral-program/)
