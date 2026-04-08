# Research: 4dedic.io and 4vps.su Tariff Data — How It Loads

## Summary

Both sites are JS-heavy. **4dedic.io** uses **pure server-side rendering** — all tariff data is baked into the HTML at request time, with `data-*` attributes on `.list__block` cards. Country selection is **client-side jQuery filtering** over pre-rendered HTML, no API call is made. **4vps.su** has a **documented public JSON API** at `/api/public/getDcList` and `/api/public/getTarifList` that returns full tariff catalogs without authentication.

---

## 4dedic.io

### Architecture: SSR + Client-Side Filter

The site is **not a true SPA** for tariff loading. Pages are server-rendered with all tariff cards embedded in the HTML. There is no XHR/fetch call to load tariff data dynamically.

### URL Pattern

Country routing is done via URL path segments:

```
https://4dedic.io/dedic/{COUNTRY_CODE}
```

Examples:
- `https://4dedic.io/dedic/RU` — Russian servers
- `https://4dedic.io/dedic/DE` — German servers
- `https://4dedic.io/dedic/SW` — Swiss servers

Each URL returns a **full HTML page** with all tariff cards for that country pre-rendered by the server.

### Tariff Card HTML Structure

Cards use class `.list__block` with data attributes for client-side filtering:

```html
<div class="list__block" data-country="sw" data-price="19800" data-ram="32" data-hdd="960">
  <h3>E3-1265Lv3</h3>
  <p>#27090</p>
  <p>цена за месяц <strong>19800 руб.</strong></p>
  <p>( 4 ядра / 8 потока)</p>
  <p>32GB DDR3</p>
  <p>1x960GB SSD</p>
  <p>1Gbit/s</p>
</div>
```

**Data attributes on `.list__block`:**

| Attribute     | Type    | Description                          | Example      |
|---------------|---------|--------------------------------------|--------------|
| `data-country`| string  | ISO-style country code               | `"sw"`, `"ru"`, `"de"` |
| `data-price`  | integer | Monthly price in rubles              | `19800`      |
| `data-ram`    | integer | RAM in GB                            | `32`         |
| `data-hdd`    | integer | Storage in GB                        | `960`        |

Note: The user mentioned `data-key` and `data-bench` — these were **not observed** in fetched HTML. They may appear on VPS-specific pages (vs dedicated servers), or may be present only after JS hydration.

### JavaScript: What It Does

No `fetch()` or `XMLHttpRequest` calls for tariff data. All JS is for:

1. **Client-side filtering** via jQuery + `ionRangeSlider` plugin — filters the pre-rendered `.list__block` cards by price, RAM, and HDD ranges
2. **Price recalculation** — `recalc(id)` and `recalc2(id)` functions compute upgrade costs using embedded JS objects:
   ```js
   ramPriceList = {"3": 500, "4": 550, ..., "61": 23200}
   romPriceList = {"5": 100, "6": 800, ..., "36": 8300}
   ```
3. **Clone synchronization** — `changeCloneItem(id)` syncs configuration selections

### What Happens on Country Click

The `.grid__block.selectCountry` selector click triggers a **page navigation** to `/dedic/{CODE}`, not a fetch. The new page is a full SSR HTML response with all cards for that country pre-rendered. The `<template id="tarifTemplate">` mentioned in the user context is likely used by the JS to stamp out cards from the embedded data, but the template's data comes from the HTML page itself, not an API.

### "API" Endpoints Tested

| URL | Response |
|-----|----------|
| `https://4dedic.io/api/tariffs` | `"Hello"` — placeholder, not tariff data |
| `https://4dedic.io/api/servers` | `"Hello"` — same placeholder |

**Conclusion: 4dedic.io has NO public tariff JSON API.** To scrape tariffs, you must fetch the HTML page at `/dedic/{CODE}` and parse the `.list__block` elements with their data attributes.

### Available Country Codes (from observed links)

`RU`, `DE`, `SW` (Switzerland), `FI`, `NL`, `PL`, `GB`, `US`, `CA`, `FR`, `PT`, `ES`, `IT`, `HK`

---

## 4vps.su

### Architecture: Public JSON API + Dynamic Rendering

4vps.su **does have a documented public REST API** with no authentication required for read-only catalog endpoints.

### Public Endpoints (No Auth Required)

#### 1. Get Panel IDs

```
GET https://4vps.su/api/public/getPanelIds
```

Response:
```json
{
  "error": false,
  "data": {
    "panelIds": [1, 2, 3]
  }
}
```

#### 2. Get Panel Details

```
GET https://4vps.su/api/public/getPanels
```

Response:
```json
{
  "error": false,
  "data": {
    "panels": {
      "west.my-server.app":    {"id": 1, "name": "west",    "vmLink": "west.my-server.app"},
      "central.my-server.app": {"id": 2, "name": "central", "vmLink": "central.my-server.app"},
      "east.my-server.app":    {"id": 3, "name": "east",    "vmLink": "east.my-server.app"}
    }
  }
}
```

The infrastructure is split into 3 panels (west / central / east), each backed by `my-server.app`.

#### 3. Get Datacenter List (PUBLIC — no auth)

```
GET https://4vps.su/api/public/getDcList
```

Returns all ~30 datacenters with pricing and preset IDs. Full response observed:

```json
{
  "datacenters": [
    {
      "id": 1,
      "name": "Арабские Эмираты, Фуджайра",
      "country_code": "ae",
      "cpu_frequency_ghz": 3.3,
      "pricing": {
        "ip_rub": 199,
        "core_rub": 200,
        "ram_gb_rub": 200,
        "disk_10gb_rub": 200
      },
      "specifications": {
        "max_cores_gb": 32,
        "max_ram_gb": 64,
        "max_disk_gb": 900
      },
      "available_presets": [15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
    },
    {
      "id": 5,
      "name": "Нидерланды, Амстердам",
      "country_code": "nl",
      "cpu_frequency_ghz": 3.5,
      "pricing": {
        "ip_rub": 199,
        "core_rub": 200,
        "ram_gb_rub": 200,
        "disk_10gb_rub": 200
      },
      "specifications": {
        "max_cores_gb": 32,
        "max_ram_gb": 64,
        "max_disk_gb": 900
      },
      "available_presets": [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
    },
    {
      "id": 15,
      "name": "Германия, Франкфурт",
      "country_code": "de",
      "cpu_frequency_ghz": 5.7,
      "pricing": {
        "ip_rub": 399,
        "core_rub": 400,
        "ram_gb_rub": 400,
        "disk_10gb_rub": 100
      },
      "specifications": {
        "max_cores_gb": 10,
        "max_ram_gb": 64,
        "max_disk_gb": 900
      },
      "available_presets": [26, 27, 28, 29, 30, 32, 33, 34, 35, 36]
    }
    // ... 27 more datacenters
  ]
}
```

**All observed datacenters (IDs):**

| ID | Location | Country | CPU GHz | Preset IDs |
|----|----------|---------|---------|-----------|
| 1  | ОАЭ, Фуджайра | ae | 3.3 | 15-25 |
| 5  | Нидерланды, Амстердам | nl | 3.5 | 13-25 |
| 8  | Германия, Франкфурт | de | 3.5 | 13-25 |
| 9  | Испания, Мадрид | sp | 3.3 | 13-25 |
| 10 | Финляндия, Хельсинки | fi | 3.3 | 13-25 |
| 11 | Великобритания, Лондон | gb | 3.3 | 13-25 |
| 12 | Франция, Париж | fr | 3.3 | 13-25 |
| 13 | Украина, Киев | ua | 3.3 | 13-25 |
| 14 | Австрия, Вена | at | 3.7 | 13-25 |
| 15 | Германия, Франкфурт (hiCPU) | de | 5.7 | 26-36 |
| 45 | Италия, Милан | it | 3.4 | 13-25 |
| 47 | Швейцария, Цюрих | sw | 3.4 | 13-25 |
| 48 | Португалия, Виана-ду-Каштелу | pt | 3.4 | 13-25 |
| 49 | Швеция, Стокгольм | swd | 3.7 | 13-25 |
| 51 | Нидерланды, Амстердам (hiCPU) | nl | 5.7 | 26-36 |
| 53 | Турция, Стамбул | tr | 3.6 | 13-25 |
| 54 | Литва, Вильнюс | lt | 3.4 | 13-25 |
| 56 | Эстония, Таллин | ee | 3.6 | 13-25 |
| 57 | Греция, Салоники | gr | 3.6 | 13-25 |
| 58 | Латвия, Рига | lv | 3.6 | 13-25 |
| 59 | Норвегия, Сандефьорд | no | 3.7 | 13-25 |
| 60 | Ирландия, Дублин | ie | 3.6 | 13-25 |
| 61 | Дания, Тендер | dk | 3.7 | 13-25 |
| 62 | Бельгия, Брюссель | be | 3.6 | 13-25 |
| 64 | Польша, Варшава | pl | 3.3 | 13-25 |
| 68 | Македония, Скопье | mk | 3.6 | 13-25 |
| 69 | Армения, Ереван | am | 3.6 | 13-25 |
| 71 | Хорватия, Загреб | hr | 3.6 | 13-25 |
| 73 | Албания, Тирана | al | 3.6 | 13-25 |
| 74 | Албания, Тирана (hiCPU) | al | 5.7 | 26-36 |
| 77 | Польша, Варшава (hiCPU) | pl | 5.7 | 26-36 |

#### 4. Get Tariff (Preset) List (PUBLIC — no auth)

```
GET https://4vps.su/api/public/getTarifList
```

Returns all tariff presets grouped by datacenter. Observed structure:

```json
{
  "datacenters": [
    {
      "id": 1,
      "location": "Арабские Эмираты, Фуджайра",
      "processor_speed": "3.3 GHz",
      "tariffs": [
        {
          "tariff_id": 15,
          "name": "AE-cx21",
          "cores": 2,
          "ram_mb": 4092,
          "disk_mb": 25600,
          "price": 1080
        },
        {
          "tariff_id": 16,
          "name": "AE-cx31",
          "cores": 4,
          "ram_mb": 4092,
          "disk_mb": 40960,
          "price": 2160
        },
        {
          "tariff_id": 25,
          "name": "AE-cx121",
          "cores": 40,
          "ram_mb": 96000,
          "disk_mb": 307200,
          "price": 43100
        }
      ]
    },
    {
      "id": 5,
      "location": "Нидерланды, Амстердам",
      "processor_speed": "3.5 GHz",
      "tariffs": [
        {
          "tariff_id": 13,
          "name": "NL-cx01",
          "cores": 1,
          "ram_mb": 1024,
          "disk_mb": 10240,
          "price": 590
        }
        // ...
      ]
    },
    {
      "id": 15,
      "location": "Германия, Франкфурт",
      "processor_speed": "5.7 GHz",
      "tariffs": [
        {
          "tariff_id": 26,
          "name": "DEr9-cx01",
          "cores": 1,
          "ram_mb": 2048,
          "disk_mb": 51200,
          "price": 1120
        }
        // ...
      ]
    }
    // ... 30 total datacenters
  ],
  "total_datacenters": 30
}
```

**Tariff fields:**

| Field | Type | Description |
|-------|------|-------------|
| `tariff_id` | int | Unique preset ID (referenced in `available_presets` from getDcList) |
| `name` | string | Human-readable plan name (e.g. `"NL-cx01"`) |
| `cores` | int | vCPU core count |
| `ram_mb` | int | RAM in megabytes |
| `disk_mb` | int | Disk in megabytes |
| `price` | int | Monthly price in rubles |

#### 5. Get Tariff Detail (PUBLIC — no auth)

```
GET https://4vps.su/api/getTarifInfo/{TARIF_ID}/{DC_ID}
```

Returns detailed tariff specs and compatible OS list for a specific preset in a specific datacenter.

### Authenticated Endpoints (require Bearer token)

All authenticated endpoints require:
```
Authorization: Bearer {API_KEY}
panel_id: {1|2|3}
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/getDcList` | Same as public but with auth context |
| GET | `/api/getTarifList` | Same as public with auth |
| GET | `/api/myservers` | List user's servers |
| POST | `/api/action/buyServer` | Purchase a VPS |
| POST | `/api/action/power_on` | Start server |
| POST | `/api/action/shutdown` | Stop server |
| POST | `/api/action/reboot` | Reboot server |
| POST | `/api/action/deleteServer` | Delete server |
| POST | `/api/action/buyIp` | Add IPs (max 64) |
| GET | `/api/iplist/{SERVER_ID}` | List server IPs |
| POST | `/api/action/getBackupPeriods` | Backup pricing |
| GET | `/api/getImages/{TARIF_ID}/{DC_ID}` | Available OS images |

### `buyServer` POST Parameters

```json
{
  "tarif": 13,
  "datacenter": 5,
  "ostempl": 42,
  "name": "my-vps",
  "domain": "optional",
  "period": 1
}
```

### How Country Selection Works on 4vps.su

The site renders a grid of 37 datacenter buttons. Clicking a country:
1. Triggers a JS handler that reads the datacenter ID from the button
2. May call `getTarifList?panel_id=X` filtered by the DC ID
3. Renders tariff cards from the `<template id="tarifTemplate">` using the fetched JSON
4. The `pingServers()` function runs on page load — sends HTTP requests to `ping-{code}.4vps.su` subdomains to measure latency, displayed alongside tariff cards

The key behavior: **clicking a country on 4vps.su does NOT trigger a new API call** for the tariff list — the full catalog is likely fetched once on page load from `/api/public/getTarifList` and then filtered client-side. The template is stamped per tariff using the JSON data.

---

## Comparison

| Feature | 4dedic.io | 4vps.su |
|---------|-----------|---------|
| Tariff loading | SSR HTML, no API | Public JSON API |
| Public API | No (Hello placeholder) | Yes (`/api/public/*`) |
| Country selection | URL navigation (`/dedic/CODE`) | Client-side filter from JS data |
| Data in HTML | Yes — data-* on `.list__block` | Dynamic via template |
| Template element | Possibly (not confirmed) | `<template id="tarifTemplate">` |
| Fetch/XHR for tariffs | No | Yes — `/api/public/getTarifList` |
| Auth required | N/A | No for read-only catalog |
| Pricing currency | Rubles (RUB) | Rubles (RUB) |
| Server count | ~498 dedicated | ~41,218 VPS |

---

## Scraping Strategy

### For 4dedic.io (HTML scraping required)

```
1. GET https://4dedic.io/dedic/{COUNTRY_CODE}
2. Parse response HTML
3. Find all elements: div.list__block
4. For each element extract:
   - data-country → location
   - data-price   → price_rub (integer)
   - data-ram     → ram_gb (integer)
   - data-hdd     → disk_gb (integer)
   - inner text   → cpu model, core count, port speed
```

Country codes observed: `RU`, `DE`, `SW`, `FI`, `NL`, `PL`, `GB`, `US`, `CA`, `FR`, `PT`, `ES`, `IT`, `HK`

### For 4vps.su (clean JSON API)

```
1. GET https://4vps.su/api/public/getDcList     → datacenter list with IDs, pricing, preset IDs
2. GET https://4vps.su/api/public/getTarifList  → all tariff presets per datacenter
3. Join on tariff_id / available_presets
4. Result: complete catalog with location, specs (cores, ram_mb, disk_mb), price_rub
```

No authentication, no JS execution required.

---

## Sources

- [4VPS.SU API Documentation](https://4vps.su/page/api)
- [4VPS.SU Public DC List](https://4vps.su/api/public/getDcList)
- [4VPS.SU Public Tariff List](https://4vps.su/api/public/getTarifList)
- [4VPS.SU Public Panel IDs](https://4vps.su/api/public/getPanelIds)
- [4dedic.io Switzerland Dedicated Servers](https://4dedic.io/dedic/SW)
- [4dedic.io VPS Page](https://4dedic.io/page/vps)
- [ISPsystem Case Study: 4VPS](https://www.ispsystem.com/cases/4vps)
- [4VPS Review](https://dieg.info/en/review/4vps-fourserver-review/)
