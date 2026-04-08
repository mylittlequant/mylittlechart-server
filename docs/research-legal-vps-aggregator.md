# Legal Research: VPS Hosting Price Aggregator — Russia & International

**Date:** 2026-04-06
**Scope:** Legal analysis for a VPS price comparison/aggregator website with affiliate links

## Business Model Summary

- Aggregate VPS pricing from ~20 providers
- Display prices and comparisons on own website
- Users click referral/affiliate links to reach providers
- Earn affiliate commission from providers on conversions
- No reselling, no billing, no user accounts, no payments processing
- No registration, no email collection, no personal forms
- Only redirect users via affiliate links

---

## 1. Personal Data Processing — 152-ФЗ

### Does an aggregator with no forms need to register as a personal data operator?

**Short answer: Yes, technically — but the obligations are minimal and manageable.**

Under Federal Law No. 152-FZ "On Personal Data," anyone who collects or processes personal data is an operator (оператор персональных данных). The key question is: what counts as personal data on a no-forms site?

**Cookies and IP addresses are considered personal data.** Russian regulators (Roskomnadzor) consistently treat cookies and IP addresses as personal data because they can indirectly identify a user. This position is upheld even when the site has no registration forms, no logins, and no explicit data entry. If the site uses:

- Google Analytics / Yandex.Metrica (standard analytics)
- Affiliate tracking cookies (e.g., Admitad click cookies)
- Any CDN or server access logs recording IPs

…then the site is processing personal data and is technically an operator under 152-FZ.

**However, the key nuance:** The law distinguishes between:
1. Technical/functional cookies (session state, load balancing) — can use "contract performance" legal basis
2. Analytics/marketing cookies — require explicit user consent

For a price comparison aggregator:
- Affiliate tracking cookies set by *your domain* before redirect = your cookies = your obligation
- Affiliate tracking cookies set by the *provider's domain* after redirect = their cookies = their obligation
- Google Analytics cookies you embed = you are co-processor with Google

**Roskomnadzor's practical position:** The regulator accepts a "transparency-first" approach. They emphasize user informativeness as the key criterion, not aggressive opt-in enforcement for low-risk sites. A pragmatic reading: if you have a visible cookie notice and a Privacy Policy, you are unlikely to face enforcement action for a simple aggregator site.

### Notification to Roskomnadzor

If you process personal data (including cookies), you must notify Roskomnadzor and be listed in the register of personal data operators. This is mandatory even for sites that only use analytics cookies.

**Exception (Article 22, Part 2 of 152-FZ):** Notification is NOT required if you process personal data exclusively for a contract with the data subject, or for personal/family/household purposes. An aggregator site does not clearly qualify for these exceptions.

**Practical minimum compliance:**
1. File a notification with Roskomnadzor (free, online at pd.rkn.gov.ru)
2. Publish a Privacy Policy (Политика конфиденциальности) — accessible without registration
3. Add a cookie consent banner (баннер согласия на cookies) — passive "continued use = consent" is technically insufficient under the strict reading of the law, but widely accepted in practice
4. Publish a Cookie Policy or section in Privacy Policy

**Fines for violation (post-2023 amendments):**
- First offense: 60,000–100,000 RUB for individuals/IP
- Repeated: 100,000–300,000 RUB
- No notification filed: up to 300,000 RUB

**Key statute:** Federal Law 152-FZ, Article 6 (legal basis for processing), Article 22 (notification)

---

## 2. Cookies and Tracking — Who Is the Data Processor?

### Affiliate cookies specifically

The answer depends on *whose domain sets the cookie*:

| Scenario | Who sets cookie | Who is processor |
|---|---|---|
| You embed affiliate JS (e.g., Admitad widget) | Admitad/provider domain | Admitad / provider |
| You redirect user to `admitad.com/r/...` link | Admitad sets on their domain | Admitad |
| You set a `click_id` cookie on your own domain to track which link was clicked | Your domain | You |
| You use Google Analytics | Google (third-party) | You + Google (joint) |

**For a simple S2S (server-to-server) postback setup with Admitad:**
- No client-side cookie is set on your domain by Admitad
- The conversion postback goes server-to-server
- You are NOT a processor of the affiliate tracking data
- Admitad processes it on their end

**For standard affiliate link redirect (no JS widgets):**
- User clicks link on your site
- Browser redirects to provider via Admitad tracking URL
- Admitad cookie set on admitad.com domain (not yours)
- You are not a processor of that specific cookie

**Your actual cookies:** If you use standard web analytics (Yandex.Metrica, Google Analytics), those cookies are set on your domain and you are an operator/co-processor. This is unavoidable for any normal website.

**Practical conclusion:** For a redirect-only aggregator using S2S postbacks, your personal data footprint is limited to analytics cookies. Provider tracking cookies after the redirect are entirely the provider's responsibility.

---

## 3. Admitad/CPA Networks — Legal Obligations

### Admitad terms for publishers

Admitad's terms for publishers explicitly state that:
- Publishers must comply with GDPR and applicable privacy laws
- Publishers must inform end users about cookies and tracking
- Publishers must maintain accurate registration data
- Publishers bear sole responsibility for their traffic quality

**Admitad's own role:** Admitad acts as a data processor for tracking data. Their Privacy Policy covers tracking URL data (click IDs, referrer URLs, country, timestamps, device/browser info) under GDPR Article 6(1)(b) as necessary for contract performance.

**Key Admitad obligations for webmasters (aggregator sites):**
1. Inform users that the site uses affiliate tracking (disclose in Privacy Policy)
2. Do not use prohibited traffic sources (fake clicks, bots, cookie stuffing)
3. Provide documentation of identity and tax info when requested
4. For Russian law compliance: Admitad is a Russian company (LLC Admajoris), so their contracts with Russian publishers are governed by Russian law

**Does Admitad handle the data processing?** Yes, for the actual tracking data (click IDs, conversions). No, for your own site's analytics cookies — those remain your responsibility.

**Cross-border transfer note (2022 amendment to 152-FZ):** If you transfer personal data outside Russia, you may need to notify Roskomnadzor before the transfer and potentially obtain approval. Admitad's servers are in multiple jurisdictions. However, for simple affiliate link redirects where you are not the data sender, this is the provider's/Admitad's obligation, not yours.

---

## 4. Advertising Law (38-ФЗ) — Ad Labeling and ОРД

### Is price comparison content "advertising"?

**Definition of advertising under 38-FZ, Article 3:**
> "Information distributed in any way, form and by any means, addressed to an indefinite circle of persons, and aimed at attracting attention to an object of advertising, forming or maintaining interest in it and its promotion on the market."

**The key distinction is: whose interest are you serving?**

| Content type | Is it advertising? | Requires labeling? |
|---|---|---|
| Your own product/service info | No (self-promotion) | No |
| Neutral catalog of providers with prices | Disputed — likely No | No (справочная информация) |
| Provider listing with promotional language ("Best deal!", "Top choice!") | Potentially Yes | Yes |
| Banner ad for specific provider with CTA | Yes | Yes |
| Affiliate link embedded in neutral comparison table | Disputed — gray area | Possibly No if catalog-style |

**The catalog exception (ФАС position):**
The Federal Antimonopoly Service (FAS Russia) has stated that information on a website that:
- Contains a uniform set of information about organizations/products
- Is grouped by categories
- Is presented as a directory/catalog

...has an informational/reference character and does NOT constitute advertising.

**Analogues in practice:**
- Avito (classifieds marketplace): listing cards are not considered advertising, only paid promo placements require labeling
- Сравни.ru, Banki.ru: use affiliate links throughout but structure content as financial product catalogs

**However, the new ОРД (Оператор Рекламных Данных) rules under Law 347-FZ (effective September 2022, enforcement from September 2023) create a new gray area:**

If your affiliate link placement qualifies as "internet advertising" under 38-FZ, you must:
1. Register as advertising distributor (рекламораспространитель) with an ОРД (e.g., Yandex ОРД, VK ОРД, Ozon ОРД, etc.)
2. Get a token (ERID — Electronic Registration ID) for each placement
3. Mark content with "Реклама" label + token + advertiser name
4. Report statistics to ERIR (Единый Реестр Интернет-Рекламы)

**Key exception confirmed (dhprime.ru analysis of Сравни.ru practice):**
Sites like Сравни.ru treat their affiliate link placements as "хозяйственная деятельность" (regular business operations/commercial activity) rather than paid advertising. Under this interpretation, own-channel monetization via affiliate links is NOT advertising requiring ОРД labeling.

**Legal risk assessment for an aggregator:**
- Low risk if: neutral catalog format, uniform presentation, no highlighted "sponsored" slots
- Medium risk if: some providers pay for featured placement, banners, highlighted boxes
- High risk if: explicit paid placements with promotional copy ("Our partner! Buy now!")

**Practical recommendation:**
- For the base catalog/comparison format: no ОРД registration needed
- For any explicit paid banner placements (if added later): must register with ОРД and label
- Keep the visual presentation neutral and consistent across all providers

**Fines for violation:** 100,000–500,000 RUB per unlabeled placement (Law 274-FZ, September 2023)

---

## 5. Tax Implications — Receiving Affiliate Income

### Legal structures available

| Structure | Tax rate | Income limit | Employees | Complexity |
|---|---|---|---|---|
| Самозанятый (НПД) | 4% from individuals, 6% from legal entities | 2.4M RUB/year | Cannot hire | Minimal |
| ИП on УСН (доходы) | 6% (may vary by region, min 1%) | No formal limit | Can hire | Low |
| ИП on ОСНО | 13–15% НДФЛ + НДС | No limit | Can hire | High |
| ООО on УСН | 6% + dividend tax | No formal limit | Can hire | Medium-High |

### Recommended: ИП on УСН 6% (доходы)

For affiliate income from VPS provider referrals:

**Самозанятый limitations:**
- 2.4M RUB/year cap (~$26K at current rates) — may be insufficient if the business scales
- Formally, self-employed cannot receive income from resale of goods — but providing leads/referrals is a service, which IS allowed
- Foreign income is allowed (самозанятый can work with foreign companies)
- 6% rate on income from legal entities (providers are legal entities)

**ИП on УСН 6% advantages:**
- No income cap
- 6% rate on all revenues
- Can receive payments in foreign currency
- Professional expense deductions are NOT available on УСН-доходы (but affiliate income has minimal costs)
- Required to pay fixed insurance contributions (~49,500 RUB/year in 2025 + 1% of income over 300K RUB)

### Receiving payments from foreign providers

Many VPS providers are foreign companies (EU, US). Options for receiving payment:

1. **Via Admitad (or similar Russian CPA network):** Admitad pays in RUB to Russian ИП/самозанятый — simplest option, no currency issues
2. **Direct from provider in foreign currency:**
   - ИП must open a foreign currency account (валютный счет) at a Russian bank
   - Income converted to RUB at CBR rate on receipt date
   - Subject to 6% УСН (no double-taxation treaty benefits for УСН taxpayers)
   - Currency control rules apply (currency repatriation requirement)
3. **Via international payment systems:** Payoneer, Wise (limited access from Russia in 2025), crypto (risky legally)

**Practical note on sanctions context (2025-2026):**
- SWIFT transfers to Russia remain problematic due to sanctions
- Many Western providers may not be able to pay Russian affiliates directly
- Using a Russian CPA network (Admitad) as intermediary is the safest path
- Alternatively: consider an EU or Georgian entity for international operations

### Tax registration requirements

- Register as ИП at nalog.ru or MFC
- Choose ОКВЭД: 73.11 (Деятельность рекламных агентств) or 73.12 (Представление в СМИ) or 63.99 (Предоставление прочих информационных услуг)
- File a УСН election within 30 days
- Annual declaration due by April 30

---

## 6. International Providers — Cross-Border Legal Issues

### Russian law perspective

For VPS providers located outside Russia (hostkey.com, ishosting.com, serverspace.io), the key question is whether they are subject to Russian law at all.

**Hosting regulation (2023 law):** Russia enacted hosting provider registration requirements (Роскомнадзор registry). This applies to **hosting providers** doing business in Russia, NOT to price comparison aggregators. As an aggregator, you are NOT a hosting provider and this law does not apply to you.

**For your affiliate contracts with international providers:**
- The contracts are governed by the provider's jurisdiction (typically EU or US)
- Russian law applies to your income tax obligations (tax on worldwide income for Russian residents)
- No specific Russian licensing requirement for running a comparison website

**Currency control:** Receiving payments from abroad in foreign currency requires:
- Валютный счет (foreign currency bank account) for ИП
- Обязательная репатриация валютной выручки has been relaxed but technically still exists for ИП
- Consult a Russian bank on current requirements

### EU providers and GDPR

If any of your listed providers are EU-based and you are directing EU users to them via affiliate links, the GDPR primarily concerns the providers, not you (as you're not processing EU user data substantively).

---

## 7. GDPR and Cookie Consent for International Visitors

### Does GDPR apply to a Russian aggregator site?

**GDPR applies if:**
- You specifically target EU users (e.g., site in European languages, EU-specific pricing)
- You monitor the behavior of EU users (analytics tracking)

A Russian VPS comparison site targeting Russian users but accessible from the EU sits in a gray zone. If the site is in Russian only and does not explicitly target EU users, GDPR enforcement is unlikely.

**However, if you use Google Analytics or similar tools that process EU user data, Google's DPA with you means you co-process that data, technically triggering GDPR obligations.**

### Affiliate cookies and GDPR consent

Under GDPR + ePrivacy Directive:
- **Strictly necessary cookies:** No consent required (e.g., session cookies, load balancing)
- **Analytics cookies:** Require consent (opt-in)
- **Affiliate tracking cookies:** Are NOT strictly necessary — require consent

**Key nuance for redirect-only model:**
If your site does NOT set affiliate cookies (only redirects to provider URLs that set their own cookies), then:
- Your site has no affiliate cookies to consent to
- The provider's cookie consent obligation kicks in after the redirect (on the provider's domain)
- Your obligation is limited to your own analytics cookies

**Practical minimum for international compliance:**
1. Use Yandex.Metrica with privacy-respecting settings (or no analytics)
2. If using Google Analytics: add cookie consent banner (GDPR requirement)
3. Simple approach: use analytics in "anonymized IP" mode or switch to server-side analytics with no client cookies

**Cookie consent banner in 2025:**
EU regulators are actively enforcing GDPR cookie consent. For EU visitors:
- Consent must be freely given, specific, informed, and unambiguous
- Pre-ticked boxes are not valid consent
- Rejection must be as easy as acceptance (no dark patterns)
- Technically: block non-essential cookies until consent given

For a Russian site not specifically targeting EU users, the enforcement risk is low. But if you want to be safe, use a Consent Management Platform (CMP) like CookieYes, Cookiebot, or Usercentrics.

---

## 8. Affiliate Terms of Service — Do Providers Prohibit Aggregators?

### Common restrictions in affiliate ToS

Based on review of major VPS/hosting affiliate programs:

**What is typically PROHIBITED:**
- Cookie stuffing (setting cookies without user interaction)
- Hidden redirects without user knowledge
- Trademark bidding in paid search (buying provider brand names as keywords)
- Creating accounts for yourself through your affiliate link
- Attracting users through deception
- Using Active Advertising Systems (CAP, WmMail, Seosprint, etc.) — Admitad policy
- Spamming

**What is NOT prohibited (or explicitly allowed):**
- Price comparison pages
- Review sites with affiliate links
- Organic SEO-driven aggregators
- Neutral product listings with affiliate buy buttons

**Specific programs reviewed:**
- **Hostinger:** Requires website/social presence; no prohibition on comparison sites
- **VirMach:** Standard affiliate terms, no aggregator restriction
- **VPSServer:** Explicitly supports comparison models; VPSBenchmarks.com is a known affiliate comparison site
- **Admitad (platform):** No restriction on price comparison sites as a traffic source type

**No major provider was found to prohibit price comparison/aggregator sites in their affiliate ToS.** This model is well-established and welcomed by providers.

**Recommendation:** Read each provider's affiliate ToS before joining. Key things to verify:
1. Is comparison/catalog traffic allowed?
2. Is "review site" traffic source permitted?
3. Are there minimum traffic requirements?
4. What's the cookie window (30/60/90 days)?

---

## 9. Price Display — Copyright and Database Rights

### Can you display VPS provider prices freely?

**Russia:**
Under Russian law, prices/tariffs are factual commercial information and are generally not subject to copyright protection. A price list is not a creative work. The database right (смежное право изготовителя базы данных, Civil Code Article 1333-1336) requires substantial investment in database creation to be protectable — and then only protects against systematic extraction.

For a comparison aggregator:
- Displaying individual prices from providers: not a copyright violation
- Copying the entire database structure of a provider's pricing page: potentially a database right issue
- Using prices obtained via provider-approved feeds or APIs: clearly permitted

**EU (Database Directive 1996/96/EC):**
The EU has a stronger "sui generis" database right. The Ryanair precedent (ECJ case with PR Aviation) established that:
- Ryanair's price data was NOT protected by database copyright
- BUT Ryanair could restrict scraping via its ToS
- If a provider's ToS prohibits scraping/aggregation, violating that ToS may be illegal even if the data itself is not copyrighted

**Practical rules for price data:**
1. **Use official feeds/APIs where available** — many providers have pricing APIs for affiliates
2. **Manual updates or limited automated crawls** — less legally exposed than aggressive scraping
3. **Attribute source:** "Prices from [Provider] as of [Date]" — reduces misrepresentation risk
4. **Check ToS for anti-scraping clauses** — Cloudflare-protected sites often have explicit ToS prohibitions

**Key principle:** The prices themselves are facts, not protectable. The collection/presentation (if it represents substantial investment) may be. For an aggregator of ~20 providers with periodically updated pricing, the risk is very low, especially when using affiliate relationships (providers are incentivized to have their prices displayed correctly).

---

## 10. Existing Russian VPS/Hosting Comparison Sites

### Known aggregators and their compliance approaches

**hostings.info**
- Major Russian/international hosting review and comparison site
- Lists hundreds of providers including Russian VPS
- Uses affiliate links to hosting providers
- Has reviews, ratings, benchmark data
- Appears to operate without explicit ОРД compliance (as catalog model)
- Accessible globally, has English and Russian versions

**servers.expert**
- Focused VPS provider catalog for Russia and CIS
- Lists providers with prices, locations, specs
- Uses affiliate/referral links
- Standard catalog format, neutral presentation

**hosting101.ru**
- Russian hosting comparison
- Review-based format
- Affiliate monetization

**VPSBenchmarks.com (international)**
- Pure benchmark/comparison data
- Explicitly acknowledges affiliate button support from providers
- "VPSBenchmarks receives support from some featured providers"
- Transparent about affiliate relationship

**Сравни.ru / Banki.ru (financial product analogues)**
- Major Russian financial product aggregators (not VPS but same legal model)
- Operate as financial marketplaces with affiliate partnerships
- Have been operating under Russian law for 10+ years
- Treated as "information services" not "advertisers" for most content
- Key insight: they treat standard product listings as хозяйственная деятельность, not advertising

### Common compliance patterns observed

1. **Privacy Policy** — all serious sites have one
2. **Cookie notice** — most have basic banners
3. **Affiliate disclosure** — minimal/none on Russian sites; present on Western sites
4. **ОРД registration** — not observed on catalog-style comparison sites
5. **152-FZ notification** — likely filed, not prominently disclosed
6. **Price attribution** — "цены актуальны на [дата]" disclaimers

---

## Summary: Minimum Viable Legal Compliance

### For a Russian VPS price aggregator with affiliate links

**Must Do (legal requirements):**

| Action | Basis | Priority |
|---|---|---|
| File notification with Roskomnadzor | 152-FZ Art. 22 | High |
| Publish Privacy Policy (in Russian) | 152-FZ | High |
| Cookie consent banner | 152-FZ / GDPR | High |
| Register as ИП or Самозанятый | Tax Code | High (before receiving income) |
| Issue receipts in "Мой налог" (if самозанятый) | НПД law | High |
| Open bank account for affiliate income | Banking law | Medium |

**Should Do (best practice / low risk without):**

| Action | Reason |
|---|---|
| Affiliate Disclosure text on site ("Сайт зарабатывает на партнерских ссылках") | Transparency, FTC/EU Directive compliance for international users |
| Date stamps on prices ("цены актуальны на...") | Avoid misrepresentation claims |
| Terms of Use / User Agreement | Basic protection |
| Read each provider's affiliate ToS before joining | Contractual compliance |

**Probably Not Required (for catalog-style site):**

| Action | Why Not Required |
|---|---|
| ОРД registration / ERID tokens | Catalog/справочная информация exception applies |
| "Реклама" labels on comparison tables | Not advertising under FAS interpretation of catalog format |
| GDPR cookie consent (if Russian-only site) | GDPR extraterritoriality does not clearly apply |
| Operator license (хостинг-оператор) | You are NOT a hosting provider |

---

## Risk Matrix

| Risk | Probability | Severity | Mitigation |
|---|---|---|---|
| 152-FZ fine for no RKN notification | Medium | Low-Medium | File notification (free, takes 1 hour) |
| ОРД fine for unlabeled affiliate links | Low (catalog model) | High (100K+ per case) | Keep neutral catalog format, no promotional copy |
| Provider terminating affiliate for ToS violation | Low | Medium | Read each program's ToS |
| GDPR enforcement from EU | Very low (Russian site) | Medium | Basic cookie consent for EU users |
| Tax liability for unreported affiliate income | Medium (if not registered) | High | Register as ИП/самозанятый before first payment |
| Copyright/database claim for price scraping | Very low (with affiliate relationships) | Low | Use affiliate feeds/APIs where possible |
| SWIFT payment issues from foreign providers | Medium | Medium | Use Russian CPA networks (Admitad) as intermediary |

---

## Key Legal References

- Federal Law No. 152-FZ "On Personal Data" (last amended 2024)
- Federal Law No. 38-FZ "On Advertising" (last amended 2024)
- Federal Law No. 347-FZ (ОРД/ERIR amendments, 2022)
- Federal Law No. 274-FZ (advertising labeling fines, September 2023)
- Tax Code of Russia, Articles 248, 346.15 (income taxation)
- GDPR Regulation (EU) 2016/679
- EU ePrivacy Directive 2002/58/EC
- EU Database Directive 96/9/EC
- ECJ Ryanair/PR Aviation case (database rights in price aggregation)

---

## Sources

- [Оператор персональных данных — data-sec.ru](https://data-sec.ru/personal-data/operator/)
- [152-ФЗ: что нужно знать, если у вас есть сайт — tochka.com](https://allo.tochka.com/personalnye-dannye)
- [Файлы cookie и персональные данные — pravo.ru](https://pravo.ru/opinion/250647/)
- [Нужно ли подавать уведомление в РКН, если сайт использует cookies — ic-tech.ru](https://ic-tech.ru/blog/faq/questions-rkn/nuzhno-li-podavat-uvedomlenie-v-rkn-esli-sayt-ispolzuet-cookies/)
- [Как маркировать партнерские материалы — 1ps.ru](https://1ps.ru/blog/texts/2024/kakoj-kontent-nuzhdaetsya-v-markirovke-reklamyi/)
- [FAQ по маркировке рекламы для веб-мастеров — Admitad](https://support.admitad.ru/knowledge-base/article/faq-%D0%BF%D0%BE-%D0%BC%D0%B0%D1%80%D0%BA%D0%B8%D1%80%D0%BE%D0%B2%D0%BA%D0%B5-%D1%80%D0%B5%D0%BA%D0%BB%D0%B0%D0%BC%D1%8B-%D0%B4%D0%BB%D1%8F-%D0%B2%D0%B5%D0%B1-%D0%BC%D0%B0%D1%81%D1%82%D0%B5%D1%80%D0%BE%D0%B2_1)
- [Маркировка рекламы в интернете 2025 — Tilda Education](https://tilda.education/advertising-labeling-2025)
- [Что не считается интернет-рекламой — okocrm.com](https://okocrm.com/blog/kakaya-reklama-ne-markiruetsya/)
- [Как маркировать рекламу при реферальных ссылках — dhprime.ru](https://dhprime.ru/blog/articles/kak-markirovat-reklamu-i-oformlyat-otchetnost-v-ord-pri-referalnykh-ssylkakh-ot-partnerskikh-program/)
- [Маркировка рекламы в интернете — Solar Staff](https://www.solarstaff.com/blog/markirovka-reklamy-v-2025-godu-novye-pravila-i-nalogi)
- [Самозанятый и иностранная компания — Tinkoff Journal](https://journal.tinkoff.ru/ask/zagraniza-i-samozanyatyi/)
- [Партнерская программа и налоги — searchengines.guru](https://searchengines.guru/showthread.php?t=216619)
- [Налогообложение иностранных доходов ИП на УСН 2025 — 1c-prime.ru](https://1c-prime.ru/articles/rekomendatsii-novye-stati-2025/nalogooblozhenie-inostrannykh-dokhodov-ip-na-usn-v-2025-godu/)
- [Do Affiliate Cookies Require Consent — TermsFeed](https://www.termsfeed.com/blog/affiliate-cookies-consent-strictly-necessary/)
- [GDPR Cookie Consent Requirements 2025 — SecurePrivacy](https://secureprivacy.ai/blog/gdpr-cookie-consent-requirements-2025)
- [Admitad Terms for Publishers](https://www.admitad.com/terms-for-publishers/)
- [Admitad Privacy Policy](https://www.admitad.com/privacy/)
- [Website scraping and database rights — pinsentmasons.com](https://www.pinsentmasons.com/out-law/news/website-operators-can-prohibit-screen-scraping-of-unprotected-data-via-terms-and-conditions-says-eu-court-in-ryanair-case)
- [EU Database Rights and scraping — Stanford Law](https://law.stanford.edu/publications/no-124-legality-and-challenges-of-web-scraping-databases-in-the-european-union-focus-on-non-personal-data-and-copyright/)
- [VPSBenchmarks — compare VPS providers](https://www.vpsbenchmarks.com/compare)
- [Hostings.info — Russia VPS ratings](https://hostings.info/hosting/ratings/best-vpsvds-hosting-providers-in-russia)
- [FTC Affiliate Disclosure rules — TermsFeed](https://www.termsfeed.com/blog/legal-agreements-affiliate-marketing/)
- [Russia data protection law overview — DLA Piper](https://www.dlapiperdataprotection.com/index.html?t=law&c=RU)
