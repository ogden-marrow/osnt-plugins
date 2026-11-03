# OSNT OSINT catalog and build plan

Research date: 2026-11-02 (upstream probes ran 2026-11-02/03 UTC from the research host, a desktop on a US residential
connection, not the Pi). Scope: find notable open-source OSINT tools and data services, screen them for safety, and plan
plugins that a builder agent can implement one batch at a time. No plugin code was written.

How to read this document:

- Section 1 is the ranked candidate table (131 rows). Tier A = build first, B = build, C = merge or low priority, X = do not build.
- Section 2 lists what was declined by the safety screen.
- Section 3 is the BUILD PLAN: 35 new plugins in 8 batches.
- Section 4 is the port table. Section 5 is the verification log and the list of things that could not be verified.
- "Verified" means a real HTTP request returned the described data from the research host on the date above. A licence
  is "verified" when read from the project's own LICENSE file or the GitHub API. Anything else is labelled "unverified" or
  "per vendor docs, not tested".

Existing plugins (do not duplicate): adsb, adsb-history, imagery, satellite, wayback (this is **Esri imagery history**, not
the Internet Archive), opendata (Maxar), lookup (DNS/RDAP/crt.sh), imgmeta, cameras, provenance, doppler, yt-mp3, map,
credentials, packages, example. Ports in use: 8101-8107, 8110, 8111, 8120-8125, 8190; 8100, 8108, 8109 are treated as reserved.

Policy applied to every candidate: passive, read-only data collection only. No active scanning of third-party hosts (port
scans, vulnerability scans, brute-force DNS), no person-targeting features, and no paid-only data.

---

## 1. Candidate table

Columns: tool, licence, what it does / key features, data sources and keys, free-tier limits, verdict and reason.
"Plan" names the planned plugin from section 3.

### 1a. Frameworks, directories and recon suites

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | C | OSINT Framework (lockfale) | MIT (verified) | Web directory of OSINT resources by category | Static site | n/a | SKIP: a link directory, not a feature; used here as an idea source |
| 2 | C | Bellingcat Online Investigation Toolkit | unverified (spreadsheet/site) | Curated toolkit with categories: maps and satellites, geolocation, image/video, archiving, companies, transport, conflict, environment, data organisation | Static | n/a | SKIP: catalogue; it drove the geolocation, archiving and verification batches |
| 3 | C | awesome-osint (jivoi) | CC BY-SA 4.0 (verified) | Large link list | Static | n/a | SKIP: link list |
| 4 | A | SpiderFoot | MIT (verified) | ~200 modules: DNS, certs, ASN, passive DNS, blocklists, threat feeds, correlation rules | Many APIs, mostly optional keys | n/a | MERGE-INTO ip-intel, subdomain-enum, ioc-lookup, domain-hygiene: module sources only; person modules declined |
| 5 | A | theHarvester | GPL-2.0 (verified) | Subdomains, hosts, IPs and emails from search engines and APIs | crt.sh, hackertarget, urlscan, etc. | n/a | MERGE-INTO subdomain-enum (host and subdomain modes only; email/people harvest declined) |
| 6 | B | Recon-ng | GPL-3.0 (verified) | Module framework: hackertarget, certificate transparency, passive DNS, whois, geolocation | Mixed | n/a | MERGE-INTO subdomain-enum |
| 7 | A | OWASP Amass | Apache-2.0 (LICENSE file says Apache2.0; GitHub API reports NOASSERTION) | Passive and active enumeration, ASN and netblock graph | Many | n/a | MERGE-INTO subdomain-enum (passive only); active brute force skipped |
| 8 | A | Subfinder | MIT (verified) | Passive subdomain discovery from ~40 sources | Optional keys | n/a | MERGE-INTO subdomain-enum |
| 9 | B | assetfinder | MIT (verified) | Passive related domains/subdomains (certspotter, hackertarget, wayback) | None | n/a | MERGE-INTO subdomain-enum |
| 10 | B | Sublist3r | GPL-2.0 (verified) | Subdomain search through engines and APIs | None | n/a | MERGE-INTO subdomain-enum |
| 11 | B | dnsx | MIT (verified) | Fast multi-record DNS resolution and wildcard filtering | DNS | n/a | MERGE-INTO domain-hygiene (via DoH, `https://dns.google/resolve` verified) |
| 12 | B | httpx | MIT (verified) | HTTP probing: status, title, tech, headers, favicon hash | Target hosts | n/a | BUILD as site-fingerprint (single-URL, SSRF-guarded, no mass probing) |
| 13 | B | tlsx | MIT (verified) | TLS cert chain, SANs, cipher and JARM-style data | Target hosts | n/a | MERGE-INTO site-fingerprint |
| 14 | A | asnmap | MIT (verified) | ASN to CIDR mapping | RIPEstat-style data | n/a | MERGE-INTO asn-bgp |
| 15 | B | mapcidr | MIT (verified) | CIDR expand/aggregate/split | Offline | n/a | MERGE-INTO cidr-exposure |
| 16 | C | uncover | MIT (verified) | Wrapper over Shodan/Censys/FOFA search keys | Paid or keyed engines | Key-bound | SKIP: key-heavy wrapper |
| 17 | X | naabu | MIT (verified) | Port scanner | n/a | n/a | SKIP: active scanning of third parties; passive InternetDB used instead |
| 18 | X | nuclei | MIT (verified) | Template vulnerability scanner | n/a | n/a | SKIP: active exploitation scanning |
| 19 | X | katana | MIT (verified) | Web crawler | n/a | n/a | SKIP: crawler; not needed |
| 20 | B | cvemap/vulnx (ProjectDiscovery) | MIT (verified, repo moved) | CVE search with KEV, EPSS and POC flags | ProjectDiscovery cloud API | Key-bound | MERGE-INTO cve-watch (same facts from open sources instead) |
| 21 | B | gau / waybackurls | gau MIT (verified); waybackurls no licence file | Harvest known URLs for a domain from Wayback, Common Crawl, OTX | CDX verified | None | MERGE-INTO web-archive |
| 22 | X | massdns / knockpy | GPL-3.0 (verified) | Brute-force subdomain resolution | n/a | n/a | SKIP: brute force, large wordlists |
| 23 | X | reconftw | MIT (verified) | Orchestrator of active recon tools | n/a | n/a | SKIP: runs offensive tools |
| 24 | X | Sn1per | Custom EULA (verified), not OSI | Offensive scanner suite | n/a | n/a | SKIP: not open source, offensive |
| 25 | X | OWASP Nettacker | Apache-2.0 (verified) | Automated penetration testing | n/a | n/a | SKIP: offensive |
| 26 | X | OWASP ZAP | Apache-2.0 (verified) | Web app scanner | n/a | n/a | SKIP: active scanner |
| 27 | C | Photon | GPL-3.0 (verified) | Crawler that extracts URLs, emails, keys | n/a | n/a | SKIP: email harvesting and crawling |
| 28 | C | FOCA / Metagoofil | GPL-3.0 / GPL-2.0 (verified) | Extract metadata (author names, software) from an organisation's public documents | Search engines | n/a | SKIP: output is mostly author names of individuals |

### 1b. Threat intelligence, exposure and vulnerabilities

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 29 | A | Shodan InternetDB | Free API | Per-IP open ports, CPEs, hostnames, tags, known CVEs (verified: `https://internetdb.shodan.io/8.8.8.8`) | No key | Fair use | BUILD via ip-intel and cidr-exposure |
| 30 | A | Shodan CVEDB | Free API | CVE detail with EPSS/KEV flag (verified `https://cvedb.shodan.io/cve/CVE-2021-44228`) | No key | Fair use | MERGE-INTO cve-watch |
| 31 | A | CISA KEV catalogue | Public domain (US gov) | Known-exploited vulnerabilities JSON (verified, 1.8 MB) | No key | None | BUILD in cve-watch |
| 32 | A | NVD CVE API 2.0 | Public (US gov) | CVE record search (verified `cveId` query) | Optional key | ~5 requests per 30 s anonymous (per vendor docs, not tested) | BUILD in cve-watch |
| 33 | A | FIRST EPSS | Free API | Exploit-prediction scores (verified) | No key | None stated | BUILD in cve-watch |
| 34 | A | OSV.dev, GitHub Advisories, MITRE cveawg | Open data / free API | Package-ecosystem and CVE 5.x records (all verified) | No key (GitHub: 60/h anonymous) | See left | BUILD in cve-watch |
| 35 | B | Exploit-DB | GPL-2.0 (unverified) | Public exploit index CSV (range request verified) | No key | None | MERGE-INTO cve-watch (links and metadata only, no exploit code stored) |
| 36 | A | abuse.ch Feodo Tracker and SSLBL | CC0 per abuse.ch (unverified) | Botnet C2 IP blocklist JSON and SSL-fingerprint blocklist (both verified, no key) | No key | None | BUILD in threat-feeds |
| 37 | A | abuse.ch URLhaus / ThreatFox / MalwareBazaar | Free for non-commercial | Malicious URL, IOC and malware-hash feeds. Verified: old anonymous export URLs return HTTP 410 and the API returns 401 without an Auth-Key | Auth-Key (free account) | Per abuse.ch | BUILD in threat-feeds with an optional `ABUSECH_AUTH_KEY`; plugin works without it |
| 38 | A | Spamhaus DROP | Free for use | Hijacked netblock list (verified, 107 KB JSON) | No key | Respect download frequency | BUILD in threat-feeds |
| 39 | A | stamparm/ipsum | Public domain (verified) | Aggregated bad-IP list with hit counts (verified, 580 KB) | No key | None | BUILD in threat-feeds |
| 40 | A | Tor Onionoo and bulk exit list | Free | Relay summary/details, exit IPs (both verified) | No key | None | BUILD in threat-feeds |
| 41 | B | OpenPhish community feed | Free tier | Phishing URL list (request returned 302, final content not verified) | No key | Per OpenPhish | MERGE-INTO threat-feeds as best-effort |
| 42 | B | PhishTank | Free key | Phishing database | Key | Per PhishTank | SKIP: registration closed/limited (unverified); OpenPhish and URLhaus cover it |
| 43 | A | urlscan.io search | Service | Search past public scans by domain/IP/hash (verified anonymous `search/` returns data) | Optional key (submission) | Anonymous search limited | BUILD in ioc-lookup; MIT client urlscan-py (verified) is only a reference |
| 44 | A | AlienVault OTX | Free API | Indicator "general" view for domain/IP/hash (anonymous domain general verified) | Optional key | Anonymous rate-limited | BUILD in ioc-lookup |
| 45 | A | GreyNoise Community | Free API | "Is this IP internet background noise or a benign service" (verified; returns 404 when unseen) | Optional key | Community limits | BUILD in ioc-lookup |
| 46 | B | AbuseIPDB | Free tier | IP abuse reports and confidence | Key required | ~1,000 checks/day (per vendor docs, not tested) | MERGE-INTO ioc-lookup (optional key) |
| 47 | B | VirusTotal | Free tier | Multi-engine reputation | Key required | ~4 requests/min (per vendor docs, not tested) | MERGE-INTO ioc-lookup (optional key) |
| 48 | B | Censys Search | Free tier | Internet host/cert search | Key required | Small free quota (unverified) | MERGE-INTO ip-intel (optional key), not planned as its own plugin |
| 49 | C | Mitaka | MIT (verified) | Browser extension: right-click IOC lookups | Many | n/a | MERGE-INTO ioc-lookup (same idea) |
| 50 | C | Harpoon (Te-k) | GPL-3.0 (verified) | CLI threat-intel pivoting | Many | n/a | MERGE-INTO ioc-lookup |
| 51 | C | MISP | AGPL-3.0 (verified) | Threat-sharing platform | n/a | Heavy server | SKIP: platform needing MySQL/Redis; public MISP feeds could be added to threat-feeds later (unverified) |
| 52 | C | OpenCTI | NOASSERTION from GitHub API (mixed; unverified) | CTI knowledge graph | n/a | Heavy | SKIP: heavy platform; graph idea goes to link-graph |
| 53 | C | Yeti | Apache-2.0 (verified) | Observable/indicator knowledge base | n/a | Heavy | SKIP: platform; idea goes to link-graph |
| 54 | X | AIL framework | AGPL-3.0 (verified) | Dark-web/leak crawling and analysis | n/a | Heavy | SKIP: dark-web leak crawling is out of scope and too heavy |
| 55 | X | TorBot | GPL-3.0 (verified) | Dark-web crawler | n/a | n/a | SKIP: out of scope |
| 56 | X | gitleaks (MIT, verified) / trufflehog (AGPL-3.0, verified) | see left | Scan repos for secrets | n/a | n/a | SKIP: credential finding |

### 1c. Network and domain data

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 57 | A | RIPEstat Data API | Open data | prefix-overview, as-overview, asn-neighbours, whois, geolocation, abuse-contact, routing-history, bgp-state (all verified) | No key | Fair use | BUILD as ip-intel and asn-bgp |
| 58 | A | PeeringDB API | CC0 data (unverified) | Networks, IXPs, facilities by ASN (verified `net?asn=15169`) | No key (anonymous throttled) | Throttled | BUILD in asn-bgp |
| 59 | B | RIPE Atlas API | Open data | Probe and measurement metadata (verified probe listing) | Optional key | Fair use | MERGE-INTO asn-bgp (probe coverage by country/ASN, read-only) |
| 60 | B | ipwho.is / ipapi.co | Free tiers | IP geolocation and ASN (both verified) | No key | ipapi.co ~1,000/day (per vendor docs, not tested) | MERGE-INTO ip-intel |
| 61 | B | Robtex free API | Free tier | IP to ASN/route (verified `freeapi.robtex.com/ipquery`) | No key | Limited | MERGE-INTO ip-intel |
| 62 | X | BGPView | Free | ASN/IP API | n/a | n/a | SKIP: request failed from research host (no response); RIPEstat covers it |
| 63 | A | Certspotter issuance API | Free tier | Certificates and DNS names for a domain (verified) | Optional key | ~100 requests/hour anonymous (per vendor docs, not tested) | MERGE-INTO subdomain-enum |
| 64 | A | HackerTarget host search | Free tier | Subdomain/IP pairs (verified) | No key | ~50 requests/day (per vendor docs, not tested) | MERGE-INTO subdomain-enum (last-resort source) |
| 65 | A | mnemonic Passive DNS | Free API | Passive DNS records (verified, 997 records for example.com) | No key | Fair use | MERGE-INTO subdomain-enum and ioc-lookup |
| 66 | C | CIRCL passive DNS | Free with account | Passive DNS | Auth (401 verified) | n/a | SKIP: needs credentials CIRCL grants manually |
| 67 | C | Anubis (jldc.me) | Unverified | Subdomain database | No key | n/a | SKIP: returned 301 only, final response not verified |
| 68 | C | RapidDNS / DNSDumpster | Unverified | Subdomains (HTML scraping / API gone) | n/a | n/a | SKIP: HTML-only or 404 |
| 69 | A | DNS-over-HTTPS (dns.google) | Free | All record types incl. DNSSEC flags (verified) | No key | Fair use | BUILD in domain-hygiene |
| 70 | B | Qualys SSL Labs API | Free for public use | TLS grading; `info` endpoint verified, assessments not run | No key | Max 7 concurrent assessments (read from `info`) | MERGE-INTO site-fingerprint (optional, read cached grade only) |
| 71 | B | Wappalyzer / wappalyzergo | Unverified (Wappalyzer changed to proprietary; wappalyzergo is MIT per upstream, not verified) | Technology fingerprinting | n/a | n/a | MERGE-INTO site-fingerprint (own small signature set, do not copy their data) |

### 1d. Organisations, sanctions and money

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 72 | A | OpenSanctions (yente MIT verified; datasets CC BY-NC per upstream, not verified) | see left | Sanctions, watchlists, debarments as one dataset. `api.opensanctions.org` returns 401 without a key. Bulk per-dataset CSVs verified without key: us_ofac_sdn 7.6 MB, eu_fsf 2.7 MB, un_sc_sanctions 0.3 MB, gb_fcdo_sanctions 7.1 MB, us_trade_csl 6.5 MB, ch_seco 3.4 MB, interpol_red_notices 1.8 MB, us_bis_denied 0.14 MB | Optional API key; bulk free | Non-commercial licence | BUILD as sanctions-screen (bulk files cached on demand) |
| 73 | A | OFAC SDN direct download | Public domain (US gov) | SDN and Consolidated CSV (verified `sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV` returns 200) | No key | None | MERGE-INTO sanctions-screen |
| 74 | B | EU, UN, UK consolidated lists | Public | EU CSV (200 verified with the public token URL); UN XML at the URL I tried returned 404 (unverified); UK CSV 50 MB (too big, use OpenSanctions slice) | No key | None | MERGE-INTO sanctions-screen |
| 75 | A | ICIJ Offshore Leaks reconciliation API | Data ODbL/CC BY-SA per ICIJ (unverified) | Entities, intermediaries, officers, addresses (verified `offshoreleaks.icij.org/api/v1/reconcile` manifest and query return 200) | No key | Fair use | BUILD as offshore-leaks; person (Officer) results restricted, see 3.3 |
| 76 | B | OCCRP Aleph / OpenAleph | MIT (verified) | Investigative document and entity search | Verified: 401 without key | Key-bound | MERGE-INTO corp-registries as optional `ALEPH_API_KEY` |
| 77 | A | GLEIF LEI API | CC0 (per GLEIF, unverified) | Legal-entity records, `fuzzycompletions` and parent relationships (verified `api.gleif.org`; `autocompletions` field unsupported, use `fuzzycompletions`) | No key | Fair use | MERGE-INTO corp-registries |
| 78 | A | SEC EDGAR | Public domain | Submissions JSON (verified), XBRL company facts (verified), company tickers (verified only with a contact-bearing User-Agent), browse-edgar Atom (verified) | UA with contact required | 10 requests/s per SEC policy (documented, not tested) | BUILD as sec-edgar. Full-text search `efts.sec.gov` returned 403 and is NOT verified |
| 79 | B | Companies House (UK) | OGL | Company search and filings | Free key (401 verified without one) | 600 requests / 5 min per docs (not tested) | MERGE-INTO corp-registries as optional key |
| 80 | B | OpenCorporates | Data ODbL-style | Global company search | Key required (401 verified) | Free for public-benefit only (unverified) | MERGE-INTO corp-registries as optional key |
| 81 | A | Nordic and Czech open registries | Open data | Norway Brreg (verified), Czech ARES (verified), Finland PRH v3 (verified), Denmark cvrapi.dk (verified, third-party wrapper) | No key | Fair use | MERGE-INTO corp-registries (company level only) |
| 82 | A | Wikidata SPARQL and entity API | CC0 | Ownership, subsidiaries, headquarters, LEI/ISIN/stock-exchange properties (both verified) | No key | Query timeouts | MERGE-INTO corp-registries and wiki-intel |
| 83 | A | USAspending API | Public domain | Awards by recipient (verified POST) | No key | None stated | BUILD as money-trail |
| 84 | A | ProPublica Nonprofit Explorer | Free API | Form 990 organisations (verified) | No key | Fair use | MERGE-INTO money-trail |
| 85 | B | Senate LDA lobbying API | Public domain | Lobbying filings (verified, redirects to `lda.gov`) | No key | Throttled | MERGE-INTO money-trail |
| 86 | B | TED (EU procurement) API v3 | Open data | Tender notices (verified POST) | No key | Fair use | MERGE-INTO money-trail |
| 87 | C | FARA eFile | Public | Foreign agent registrations | Unverified (page only reachable, API not tested) | n/a | SKIP: API not verified |

### 1e. Events, news and public-source monitoring

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 88 | A | GDELT DOC 2.0 and event/GKG files | Open (attribution) | Article search, timelines, tone (verified once the 5-second spacing and a contact UA were respected); `lastupdate.txt` 15-minute export list verified; the `geo/geo` endpoint returned 404 | No key | 1 request per 5 s (verified by HTTP 429 message) | BUILD as gdelt-news |
| 89 | B | ACLED API | Free registration, research terms | Armed-conflict events | Key + email; host did not respond (unverified) | Terms-limited | MERGE-INTO conflict-events (optional key) |
| 90 | B | UCDP GED API | CC BY 4.0 per UCDP (unverified) | Georeferenced conflict events (verified: 401 until `x-ucdp-access-token` supplied) | Free token | Per UCDP | BUILD as conflict-events (token required) |
| 91 | A | Wikimedia APIs (On this day, EventStreams, pageviews, Commons) | CC BY-SA / CC0 | Current events, edit stream (verified SSE), page-view spikes, geosearch (verified) | No key | Fair use | BUILD as wiki-intel |
| 92 | A | RSS/Atom monitoring (e.g. ThreatIngestor idea, Feedly-style) | n/a | Poll feeds, keyword alerts, dedupe | User-supplied feeds | n/a | BUILD as rss-watch; fetches through an SSRF guard |
| 93 | C | Telegram public-channel monitoring | n/a | `t.me/s/<channel>` preview pages for channels | Unverified | n/a | MERGE-INTO rss-watch as opt-in for public channels only (no groups, no members, no users); fetch not verified |
| 94 | C | Liveuamap, ISW maps | Not open | Conflict maps | n/a | n/a | SKIP: no open API or licence |
| 95 | C | Hacker News Algolia API | Free | Story/comment search (verified) | No key | None stated | MERGE-INTO rss-watch (keyword alert source) |

### 1f. Geolocation helpers

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 96 | A | SunCalc | BSD-2-Clause (verified) | Sun azimuth and altitude, shadow length, sunrise/sunset | Offline math (plus `api.sunrise-sunset.org` verified as a cross-check) | None | BUILD as sun-shadow |
| 97 | A | Bellingcat ShadowFinder | MIT (verified) | Find candidate latitudes/longitudes from a shadow length, date and time | Offline math | None | MERGE-INTO sun-shadow |
| 98 | A | Open-Meteo archive and forecast | CC BY 4.0 (per upstream, unverified); free non-commercial | Hourly cloud cover, temperature, history (verified) | No key | ~10,000 calls/day non-commercial (per vendor docs, not tested) | MERGE-INTO sun-shadow (was it cloudy at claimed time) |
| 99 | A | Overpass API and Overpass Turbo | AGPL for software per upstream, ODbL data (unverified) | Query OSM features by tag/area; geolocation by matching features | No key | Instance policy | BUILD as osm-query. **Not verified**: `overpass-api.de` returned HTTP 406 to every probe from the research host and two alternative instances did not respond; builders must test from the Pi and make the instance URL configurable |
| 100 | A | Nominatim and Photon | ODbL data | Geocoding and reverse geocoding (both verified) | No key | Nominatim: 1 request/s, UA required | MERGE-INTO osm-query |
| 101 | B | OSM changesets and notes API | ODbL | Recent edits and map notes in a box (both verified) | No key | Fair use | MERGE-INTO osm-query |
| 102 | A | Elevation APIs and Terrarium tiles | Open data | Open-Meteo elevation (verified), OpenTopoData SRTM (verified), AWS Terrarium PNG tiles (HEAD verified) | No key | Fair use | BUILD as terrain-view (horizon and line-of-sight) |
| 103 | B | Mapillary and KartaView | Mapillary CC BY-SA imagery | Street-level imagery | Mapillary needs token (verified 500 OAuth error without); KartaView no response | Free token | MERGE-INTO place-photos (optional `MAPILLARY_TOKEN`) |
| 104 | A | Wikimedia Commons geosearch | CC licences | Geotagged place photos (verified) | No key | Fair use | BUILD as place-photos |
| 105 | B | Coordinate and geodesy utilities (MGRS, UTM, geohash, Plus Codes) | Offline | Conversions, distance and bearing, KML/GeoJSON export | Offline | None | BUILD as geo-toolkit |

### 1g. Hazards, space, transport and maritime

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 106 | A | USGS earthquake feeds, EMSC FDSN, NOAA tsunami.gov | Public | GeoJSON quakes (USGS, EMSC verified), tsunami Atom (verified) | No key | None | BUILD as quake-tsunami |
| 107 | A | GDACS, NASA EONET, NWS alerts, Smithsonian volcano RSS, USGS HANS volcano, NHC storms | Public / open | Multi-hazard events (GDACS GeoJSON, EONET, NWS `?area=CA`, GVP weekly RSS, HANS elevated-volcano JSON, NHC `CurrentStorms.json` all verified; the NWS `limit` parameter is rejected) | No key | None | BUILD as hazard-events |
| 108 | B | ReliefWeb API v2 | CC BY | Humanitarian reports and disasters | Approved `appname` required (v1 decommissioned HTTP 410; v2 returned 403 without approval) | Registration | MERGE-INTO hazard-events (optional `RELIEFWEB_APPNAME`) |
| 109 | A | NASA FIRMS | Public | Active-fire CSV: global 24 h file verified without a key (6 MB); area/country API needs a MAP_KEY (`DEMO_KEY` rejected) | Optional MAP_KEY | Per NASA | BUILD as fire-watch; extends the existing imagery plugin's fire layer with statistics and area watches |
| 110 | A | Launch Library 2 | Free API | Launch schedule and agencies (verified) | No key | ~15 requests/hour anonymous (per vendor docs, not tested) | BUILD in space-watch |
| 111 | A | CelesTrak GP | Free | Orbital elements and satellite catalog queries (verified JSON for ISS) | No key | Fair use | MERGE-INTO space-watch (object catalogue, not passes; doppler/satellite already exist) |
| 112 | B | NASA DONKI space weather | Public | Flares and CMEs | `DEMO_KEY` request did not respond (unverified) | Key-bound | SKIP: not verified |
| 113 | A | Digitraffic Finland AIS and rail | CC BY 4.0 per Digitraffic (unverified) | Live vessel positions and metadata (verified, 858 KB), live trains (verified); both require `Accept-Encoding: gzip` or return 406 | No key | Fair use | BUILD as ais-vessels and rail-live (Baltic/Finnish coverage) |
| 114 | B | AISStream.io, Global Fishing Watch | Free key | Global AIS WebSocket (handshake reached), fishing-effort events | Free keys | Per vendor | MERGE-INTO ais-vessels as optional keys |
| 115 | A | NGA Maritime Safety Information | Public | Navigational warnings (verified `broadcast-warn`), ASAM piracy reports and port index (same host, not individually tested) | No key | None | BUILD as maritime-notices |
| 116 | A | adsbdb.com and hexdb.io | Free | Aircraft registration/type and callsign route (both verified) | No key | Fair use | BUILD as aircraft-registry |
| 117 | B | OpenSky, adsb.lol, airplanes.live | Free | Live ADS-B. Verified: OpenSky anonymous bbox, adsb.lol v2 point. airplanes.live returned 403 asking for contact; adsb.fi unreachable | No key | OpenSky anonymous limited | MERGE-INTO adsb as extra sources; no new plugin |
| 118 | C | Flightradar24, FlightAware, MarineTraffic, VesselFinder | Proprietary | Commercial trackers | Paid | n/a | SKIP: paid |
| 119 | C | OpenRailwayMap | ODbL data | Railway map tiles (site verified) | No key | Tile policy | MERGE-INTO rail-live as a map overlay |
| 120 | C | GPSJam-style GNSS interference map | n/a | Derived from ADS-B accuracy fields | Existing adsb-history data | n/a | MERGE-INTO adsb-history later (not a new plugin) |

### 1h. Media verification, archiving and investigator tools

| # | Tier | Tool | Licence | What it does / key features | Data / keys | Free-tier limits | Verdict |
|---|---|---|---|---|---|---|---|
| 121 | A | InVID-WeVerify verification plugin | Licence not found at the repository path I tried (unverified) | Video keyframes, thumbnails, magnifier, forensic filters, reverse-search launchers | Local | n/a | BUILD as media-verify (keyframes and links; filters already in imgmeta) |
| 122 | B | C2PA / Content Credentials (c2pa-rs) | Apache-2.0/MIT per upstream (unverified) | Read signed provenance manifests | Local | n/a | MERGE-INTO media-verify (pure-Rust feasibility must be checked first) |
| 123 | C | FotoForensics / Ghiro | n/a | ELA and metadata | n/a | n/a | SKIP: ELA already in imgmeta |
| 124 | C | ExifTool / exif-py | exif-py BSD-style (verified); ExifTool not checked | EXIF extraction | Local | n/a | SKIP: covered by imgmeta |
| 125 | A | Internet Archive Wayback CDX and Save Page Now | Free | Snapshot index (CDX verified), `timemap` (200 verified); availability API returned 429 under repeat load; `save/` returned a redirect, full behaviour not verified | No key | Rate limited | BUILD as web-archive |
| 126 | A | Common Crawl index | Open data | URL index per crawl (`collinfo.json` verified) | No key | Fair use | MERGE-INTO web-archive |
| 127 | C | archive.today | n/a | On-demand page snapshots | CAPTCHA | n/a | SKIP: CAPTCHA-gated, no API; link-out only |
| 128 | A | Bellingcat Auto Archiver | MIT (verified) | Archive URLs, hash evidence, timestamps, optional Wayback/ screenshots | Local | n/a | MERGE-INTO case-notebook and web-archive (evidence log idea) |
| 129 | C | ArchiveBox (MIT), SingleFile (AGPL-3.0), pywb (GPL-3.0) | verified | Self-hosted archiving, browser capture, replay | Headless browser | Heavy | SKIP: need a headless browser; use web-archive hashing and Wayback instead |
| 130 | A | Maltego-style link analysis (Maltego is proprietary; open: Cytoscape.js, vis-network, Gephi) | Libraries per upstream (unverified) | Entity graph with "transforms" | Local plus other plugins | n/a | BUILD as link-graph (objects only, no person entity type) |
| 131 | A | Case notes (Obsidian, Hunchly, CherryTree idea) | Hunchly paid | Notes, evidence, timeline | Local redb | n/a | BUILD as case-notebook |

Totals: 131 rows (see section 6 for the verdict counts).

---

## 2. Declined by the safety screen

These are not built, are not merged and no partial version is planned. If a candidate above says "person modules declined"
the same rule applies to that part.

| Candidate | Reason |
|---|---|
| Sherlock (MIT, verified), Maigret (MIT, verified), Social-Analyzer, WhatsMyName-style lookups | Username/handle enumeration across social sites |
| Holehe (GPL-3.0, verified), Epieos, Ignorant, Hunter.io | Email-to-account/person lookups |
| PhoneInfoga (GPL-3.0, verified), reverse phone lookups, Truecaller-style data | Phone-number-to-person lookups |
| HaveIBeenPwned, DeHashed, IntelX, breach-credential search (including theHarvester's email and people modules) | Breach-credential lookups about individuals |
| PimEyes, FaceCheck.ID, Clearview, any face recognition or embedding matcher | Identifying people from images |
| Voice, speaker or gait identification | Identifying people from audio or video |
| Pipl, Spokeo, TruePeopleSearch, FastPeopleSearch, address-of-a-person lookups | People-search |
| snscrape, twint, Osintgram, Toutatis (Instagram), Instaloader-style, Reddit/Telegram user-history analysers, Telegram user and group-member scrapers | Social-media scraping of personal accounts |
| GHunt (NOASSERTION in GitHub API), Gravatar-hash pivots, GitHub commit-email harvesting | Personal account/email deanonymisation |
| WiGLE-style Wi-Fi/Bluetooth and cell-ID databases queried by BSSID/MAC | Can locate an individual's home router or device |
| Licence-plate lookup/ALPR, Find My / AirTag tracking, Strava/Snapchat map scraping, any live-tracking of a person | Stalkerware-like or live-tracking of a person |
| WikiScanner-style "which IP edited this article" attribution | Attributes anonymous editors, who are individuals |
| GeoSpy, Picarta and similar AI "locate this photo" services | Paid/commercial and mostly used to locate people; ordinary geolocation helpers (sun, OSM, terrain) are built instead |
| Doxxing aids and "find everything about a person" aggregators (including Maltego person transforms) | Doxxing |
| Shodan Search, Censys paid tiers, FlightRadar24 API, MarineTraffic API, Maxar paid imagery, SecurityTrails, Spur, DomainTools, Hunchly | Paid/commercial data the user does not have, where no useful free tier exists |

Related decisions worth knowing:

- Sanctions, Offshore Leaks and company registries contain named individuals. Section 3 restricts each of them (names and
  listing facts only for designated persons; no addresses, dates of birth or identifiers for natural persons; officer
  search off by default).
- ELA, EXIF and provenance checks are allowed (non-identifying). Face matching is never added to media-verify.

---

## 3. BUILD PLAN: 35 new plugins in 8 batches

Common rules for every plugin (builders also read `.claude/skills/osnt-plugin/SKILL.md`):

- Pure Rust, loopback only, relative URLs, `GET /tools`, a cache with TTL on every upstream, a descriptive User-Agent.
  Where the upstream wants a contact in the User-Agent (SEC, Nominatim, GDELT courtesy), build it as
  `osnt-<id>/0.1 (+https://github.com/ogden-marrow/osnt-hub)`; SEC additionally needs a real contact (see sec-edgar).
- Fixed upstream hosts only. Plugins that fetch user-supplied URLs (rss-watch, site-fingerprint, web-archive capture,
  media-verify) copy the guard from `plugins/provenance/src/ssrf.rs`.
- Where an upstream requires `Accept-Encoding: gzip` (Digitraffic), enable ureq's gzip feature or inflate with a
  pure-Rust crate (`miniz_oxide`/`flate2` with the `rust_backend` feature).
- Persist only what the plugin needs, in `state_dir` with redb. Large bulk files (sanctions lists, FIRMS CSV) are
  downloaded on demand, parsed, cached for hours and bounded in size.
- "Needs [system] package: no" unless stated.

Launcher grids to use (existing: Network & Infrastructure, Geospatial, Air & Sea, Media & Verification; new: Threat Intel,
Organisations, Events & News, Hazards, Investigation).

### Batch 1: Infrastructure recon (no keys, rock-solid free APIs, lowest risk)

**1.1 `ip-intel` — IP intelligence** (grid: Network & Infrastructure)
- Features (SpiderFoot, Recon-ng, Harpoon, ipinfo-style): one IP or hostname gives an overview card with ownership,
  routing, exposure and reputation:
  - Ownership and routing from RIPEstat `prefix-overview`, `whois`, `abuse-contact-finder`, `maxmind-geo-lite`.
  - Exposure from Shodan InternetDB (ports, CPEs, hostnames, tags, CVEs).
  - Geolocation cross-check from ipwho.is and ipapi.co with a "sources disagree by N km" flag.
  - Membership checks: Tor exit list, Spamhaus DROP.
  - Robtex route/ASN name.
- Verified upstreams: `https://stat.ripe.net/data/{prefix-overview,as-overview,whois,maxmind-geo-lite,abuse-contact-finder}/data.json?resource=...`;
  `https://internetdb.shodan.io/<ip>`; `https://ipwho.is/<ip>`; `https://ipapi.co/<ip>/json/`;
  `https://check.torproject.org/torbulkexitlist`; `https://www.spamhaus.org/drop/drop_v4.json`;
  `https://freeapi.robtex.com/ipquery/<ip>`.
- Secrets: `CENSYS_API_ID` / `CENSYS_API_SECRET` (both optional; adds a Censys host view). Not verified (no key).
- [system]: no.
- UI: one search box; result cards (Owner, Routing, Exposure, Reputation, Geo), a small map with each geolocation
  source as a differently coloured marker, copy-as-JSON. Tools: `ip_overview`, `ip_exposure`, `ip_lists`.

**1.2 `asn-bgp` — ASN and BGP explorer** (grid: Network & Infrastructure)
- Features (asnmap, Amass netblock graph, bgp.tools-style): ASN overview and holder; announced prefixes; upstream and
  downstream neighbours; routing history for a prefix (origin changes, which is how hijack and re-homing stories are
  spotted); current BGP state per RIS peer; PeeringDB networks, IXPs and facilities for an ASN; RIPE Atlas probe counts
  by country or ASN.
- Verified upstreams: RIPEstat `as-overview`, `asn-neighbours`, `routing-history`, `bgp-state`, `announced-prefixes` (not tested; same family);
  `https://www.peeringdb.com/api/net?asn=15169`; `https://atlas.ripe.net/api/v2/probes/?country_code=NL&page_size=1`.
- Secrets: `PEERINGDB_API_KEY` (optional; raises the anonymous throttle).
- [system]: no.
- UI: ASN box; neighbour graph (up/peer/down in three columns); prefix table with a route-history timeline.
  Tools: `asn_overview`, `asn_prefixes`, `asn_neighbours`, `prefix_history`, `asn_peeringdb`.

**1.3 `subdomain-enum` — Passive subdomain discovery** (grid: Network & Infrastructure)
- Features (Subfinder, Amass passive, assetfinder, Sublist3r, theHarvester host mode, Recon-ng): merge subdomains from
  many passive sources, show which source saw each name, resolve each with DoH (A/AAAA/CNAME) to mark live/dead,
  highlight dangling CNAMEs, export CSV. Brute-force and zone-transfer attempts are deliberately not included.
- Verified upstreams: Certspotter `https://api.certspotter.com/v1/issuances?domain=D&include_subdomains=true&expand=dns_names`;
  `https://api.hackertarget.com/hostsearch/?q=D`; mnemonic `https://api.mnemonic.no/pdns/v3/D`;
  urlscan `https://urlscan.io/api/v1/search/?q=domain:D`; Wayback CDX `https://web.archive.org/cdx/search/cdx?url=*.D&output=json&fl=original&collapse=urlkey`
  (base CDX verified; wildcard form not tested); OTX `https://otx.alienvault.com/api/v1/indicators/domain/D/passive_dns`
  (section "passive_dns" listed in the verified general response); `https://dns.google/resolve`. crt.sh stays in `lookup` (call it via `requires = ["lookup"]`).
- Secrets: `CERTSPOTTER_API_KEY`, `VIRUSTOTAL_API_KEY` (both optional; more results).
- [system]: no.
- UI: table (name, sources, resolves-to, status), source filter chips, progress per source because some are slow.
  Tools: `subdomains_find`, `subdomains_resolve`.

**1.4 `domain-hygiene` — DNS, mail and policy checks** (grid: Network & Infrastructure)
- Features (dnsx, SpiderFoot DNS modules, MXToolbox-style): all record types via DoH; SPF include chain with lookup
  count; DMARC policy; DKIM selector probe (common selectors); MTA-STS and TLS-RPT; BIMI; CAA; DNSSEC AD flag and
  DS/DNSKEY; NS delegation sanity; wildcard detection; `/.well-known/security.txt` and robots/sitemap URLs via
  an SSRF-guarded fetch. Output is a scored checklist with explanations. No individual's data.
- Verified upstream: `https://dns.google/resolve?name=D&type=MX` (JSON, includes AD flag). Cloudflare DoH returned HTTP 400
  without the `accept: application/dns-json` header (not retested with it); use dns.google as primary.
- Secrets: none.
- [system]: no.
- UI: domain box; checklist (pass/warn/fail) with a raw-record drawer; SPF tree view. Tools: `domain_records`, `domain_mail_policy`, `domain_dnssec`.

### Batch 2: Threat intel and exposure (mostly keyless feeds)

**2.1 `cve-watch` — Vulnerability watch** (grid: Threat Intel)
- Features (cvemap/vulnx, Shodan CVEDB, CISA KEV): CVE lookup that merges NVD description and CVSS, CISA KEV status
  with due date and ransomware-use flag, EPSS score and percentile, MITRE record, OSV and GitHub advisory for package
  IDs; "latest KEV additions" feed; search by product/keyword; exploit-reference links from Exploit-DB metadata (links
  only, no exploit code stored); watchlist of products with an "added since last visit" badge.
- Verified upstreams: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-...`;
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`;
  `https://api.first.org/data/v1/epss?cve=CVE-...`; `https://api.osv.dev/v1/vulns/<id>`;
  `https://cveawg.mitre.org/api/cve/CVE-...`; `https://api.github.com/advisories?per_page=N`;
  `https://cvedb.shodan.io/cve/CVE-...`.
- Secrets: `NVD_API_KEY` (optional; higher rate), `GITHUB_TOKEN` (optional).
- [system]: no.
- UI: CVE card with severity badge, KEV/EPSS gauges, references; "recent KEV" table; watchlist panel. Tools: `cve_lookup`, `kev_recent`, `cve_search`, `osv_lookup`.

**2.2 `threat-feeds` — Open blocklists and IOC membership** (grid: Threat Intel)
- Features (SpiderFoot blocklist modules, ThreatIngestor idea, abuse.ch): refresh and cache Feodo Tracker C2 IPs,
  SSLBL JA3/IP blacklist, Spamhaus DROP, ipsum, Tor exit list, Onionoo relay lookups, best-effort OpenPhish, and (with a
  key) URLhaus, ThreatFox and MalwareBazaar recent items. Core feature: "is this IP, CIDR, domain, URL or hash in any
  feed, and since when". Per-feed freshness shown.
- Verified upstreams: `https://feodotracker.abuse.ch/downloads/ipblocklist.json`;
  `https://sslbl.abuse.ch/blacklist/sslipblacklist.csv`; `https://www.spamhaus.org/drop/drop_v4.json`;
  `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`; `https://check.torproject.org/torbulkexitlist`;
  `https://onionoo.torproject.org/summary?limit=N`. Not working anonymously (verified): URLhaus, ThreatFox and
  MalwareBazaar old exports return 410 and `urlhaus-api.abuse.ch` returns 401. OpenPhish feed returned a redirect (unverified).
- Secrets: `ABUSECH_AUTH_KEY` (optional; enables URLhaus/ThreatFox/MalwareBazaar). Free key from abuse.ch.
- [system]: no.
- UI: omni-search box (IP/domain/hash), per-feed tiles with counts and last refresh, table of recent entries. Tools: `feeds_check`, `feeds_recent`, `tor_relay`.

**2.3 `ioc-lookup` — Multi-source reputation** (grid: Threat Intel)
- Features (Mitaka, Harpoon, SpiderFoot): one indicator (IP, domain, URL, file hash) fanned out to urlscan search,
  OTX general, GreyNoise Community, mnemonic passive DNS, InternetDB and, if keys exist, VirusTotal and AbuseIPDB.
  Shows a per-source verdict row and never claims a combined score it cannot justify. Optional urlscan scan submission
  is NOT included by default (it sends the URL to a third party); a toggle with a warning may enable it when
  `URLSCAN_API_KEY` is set.
- Verified upstreams: `https://urlscan.io/api/v1/search/?q=...`; `https://otx.alienvault.com/api/v1/indicators/{domain|IPv4|file|url}/<x>/general`
  (domain verified); `https://api.greynoise.io/v3/community/<ip>` (verified, 404 JSON for unseen IPs);
  `https://api.mnemonic.no/pdns/v3/<x>`; `https://internetdb.shodan.io/<ip>`.
- Secrets: `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY` (all optional).
- [system]: no.
- UI: one box, a table of sources x verdict with links to the upstream page; sources without a key shown greyed with a hint to the Credentials page. Tools: `ioc_lookup`.

**2.4 `cidr-exposure` — Netblock exposure summary** (grid: Threat Intel)
- Features (mapcidr, passive Shodan-style summaries, naabu replaced by passive data): expand a CIDR (capped at /24
  by default, configurable up to /22), query InternetDB per address at a polite rate, aggregate open ports, products
  (CPEs), vulnerable hosts and hostnames; heatmap of the block; CSV export. Entirely passive: no packets are sent to the targets.
- Verified upstreams: `https://internetdb.shodan.io/<ip>` (no key).
- Secrets: none.
- [system]: no.
- UI: grid of cells per address (colour by risk tag), port histogram, filter by CVE or product. Tools: `cidr_summary`.

**2.5 `site-fingerprint` — One-URL web fingerprint** (grid: Network & Infrastructure)
- Features (httpx, tlsx, Wappalyzer idea): for a single user-supplied URL (SSRF-guarded, redirects capped and shown):
  status chain, server and framework headers, small built-in technology signature set (builder writes their own),
  security-header scorecard, cookies flags, title/meta/generator, robots and sitemap summary, favicon hash (mmh3 value
  for pivoting in other tools), TLS chain, validity dates and SANs, HTTP/2 or HTTP/3 advertised. Optional cached SSL Labs grade (reads, does not start, assessments).
- Verified upstream: SSL Labs `https://api.ssllabs.com/api/v3/info` only (assessment endpoints untested).
- Secrets: none.
- [system]: no.
- UI: URL box; sections for Redirects, Headers, Tech, TLS, Files. Tools: `site_fingerprint`.

### Batch 3: Organisations and sanctions

**3.1 `sec-edgar` — SEC EDGAR company filings** (grid: Organisations)
- Features: company lookup by name or ticker (company_tickers, browse-edgar Atom), submissions history with form-type
  filter, latest 8-K/10-K/10-Q/20-F/S-1 links, XBRL company facts (revenue, assets, shares), Exhibit 21 subsidiary list
  link, state of incorporation, SIC code, former names, business and mailing address of the company. Filings listing
  individuals (Forms 3/4/5, 13D by named holders) are shown only as filing metadata, no person pages or tracking.
- Verified upstreams: `https://data.sec.gov/submissions/CIK##########.json`;
  `https://data.sec.gov/api/xbrl/companyconcept/CIK##########/us-gaap/<tag>.json`;
  `https://www.sec.gov/files/company_tickers.json` (200 with a contact-bearing User-Agent, 403 with a generic one);
  `https://www.sec.gov/cgi-bin/browse-edgar?company=...&action=getcompany&output=atom`.
  NOT verified: `https://efts.sec.gov/LatestSearch/rest/search-index` (full-text search) returned 403 even with a contact UA; builder must retest and otherwise omit.
- Secrets: `SEC_CONTACT` (required: a contact email/URL for the User-Agent. This is a declaration, not a credential; the plugin refuses to call SEC without it, per SEC fair-access policy).
- [system]: no.
- UI: company search, filing timeline, facts sparkline. Tools: `sec_company`, `sec_filings`, `sec_facts`.

**3.2 `sanctions-screen` — Sanctions and watchlist screening** (grid: Organisations)
- Features (OpenSanctions/yente, OFAC Sanctions List Search): fuzzy name search over official lists downloaded on demand
  and cached: OFAC SDN (direct), EU FSF, UN SC, UK FCDO (via OpenSanctions slice), US Trade CSL, SECO, US BIS Denied
  Persons, Interpol Red Notices excluded (see below). Entity types: company, organisation, vessel, aircraft; results
  show list, programme, listing date, aliases and links. Cross-check helper takes a vessel IMO/MMSI or aircraft
  registration from `ais-vessels`/`aircraft-registry`. Match-quality scoring is explained (token/phonetic, shown).
- Safety decisions: natural persons on official lists are returned as name, list, programme and listing date only (no
  date of birth, address or ID numbers); Interpol Red Notices are excluded entirely (they describe individuals, not organisations).
- Verified upstreams (bulk, no key): `https://data.opensanctions.org/datasets/latest/{us_ofac_sdn,eu_fsf,un_sc_sanctions,gb_fcdo_sanctions,us_trade_csl,ch_seco_sanctions,us_bis_denied}/targets.simple.csv`
  (all return 200 after a redirect, 0.14-7.6 MB); `https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV`.
  `https://api.opensanctions.org/*` returned 401 (key required). Licence of OpenSanctions datasets is non-commercial; show attribution in the UI.
- Secrets: `OPENSANCTIONS_API_KEY` (optional; enables the match API, not verified).
- [system]: no.
- UI: search box with list checkboxes, results table with listing details, "list freshness" strip. Tools: `sanctions_search`, `sanctions_lists`.

**3.3 `offshore-leaks` — ICIJ Offshore Leaks lookups** (grid: Organisations)
- Features: reconciliation search over ICIJ's Offshore Leaks database restricted to entities (companies, trusts,
  foundations), intermediaries and addresses-as-jurisdictions; entity detail with jurisdiction, status, incorporation
  date, source leak (Panama/Paradise/Pandora/etc.), and links to the ICIJ node page; relationship summary counts.
  Officer (individual) records are not searched by default; the endpoint is queried with type filters
  `Entity` and `Intermediary` only.
- Verified upstream: `https://offshoreleaks.icij.org/api/v1/reconcile` (manifest) and
  `...reconcile?queries={"q0":{"query":"mossack"}}` (200). The search page `offshoreleaks.icij.org/search` returned HTTP 202 (queued) and is not used.
- Secrets: none.
- [system]: no.
- UI: search, result list with leak badges and a jurisdiction map; no relationship drill-down into individuals. Tools: `leaks_entity_search`, `leaks_entity`.

**3.4 `corp-registries` — Company registries and ownership** (grid: Organisations)
- Features: GLEIF (legal-entity record, direct and ultimate parent, `fuzzycompletions`), Wikidata SPARQL (owned by,
  subsidiaries, headquarters, identifiers), national open registries (Norway Brreg, Czech ARES, Finland PRH, Denmark
  CVR wrapper) and, with keys, Companies House, OpenCorporates and OCCRP Aleph. Output is company-level only: legal name,
  status, registered address of the company, industry codes, parent/subsidiary links; officers, directors and
  shareholder individuals are not displayed.
- Verified upstreams: `https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=...`;
  `https://api.gleif.org/api/v1/fuzzycompletions?field=entity.legalName&q=...`;
  `https://query.wikidata.org/sparql`; `https://data.brreg.no/enhetsregisteret/api/enheter?navn=...`;
  `https://ares.gov.cz/ekonomicke-subjekty-v-be/rest/ekonomicke-subjekty/<ico>`;
  `https://avoindata.prh.fi/opendata-ytj-api/v3/companies?name=...`; `https://cvrapi.dk/api?search=...&country=dk`.
  Parent relationship endpoints returned 404 for the single LEI I tried (that entity may have no reported parent); builder must test a known subsidiary.
- Secrets: `COMPANIES_HOUSE_API_KEY`, `OPENCORPORATES_API_TOKEN`, `ALEPH_API_KEY` (all optional; each 401 verified without a key).
- [system]: no.
- UI: unified search, side-by-side registry cards, ownership tree (GLEIF + Wikidata). Tools: `corp_search`, `corp_lei`, `corp_ownership`.

**3.5 `money-trail` — Public funds and procurement** (grid: Organisations)
- Features: USAspending awards and contracts by recipient organisation (totals by year, top agencies); ProPublica
  Nonprofit Explorer (Form 990 revenue, assets, organisation details); Senate LDA lobbying filings by client or
  registrant organisation; EU TED tender notices by buyer or winner organisation. Organisation-level only.
- Verified upstreams: `POST https://api.usaspending.gov/api/v2/search/spending_by_award/`;
  `https://projects.propublica.org/nonprofits/api/v2/search.json?q=...`;
  `https://lda.senate.gov/api/v1/filings/?filing_year=YYYY&page_size=N` (redirects to `lda.gov`);
  `POST https://api.ted.europa.eu/v3/notices/search`.
- Secrets: none.
- [system]: no.
- UI: organisation box; four tabs (Awards, Nonprofit, Lobbying, Tenders) with totals and sparklines; CSV export. Tools: `money_awards`, `money_nonprofit`, `money_lobbying`, `money_tenders`.

### Batch 4: Geolocation helpers

**4.1 `sun-shadow` — Sun, shadow and time verification** (grid: Geospatial)
- Features (SunCalc, Bellingcat ShadowFinder): sun azimuth/altitude for lat/lon/time; shadow length and direction for an
  object height; "time of day from shadow length" and "candidate latitudes from shadow length, date and time"
  (ShadowFinder-style band on the map); day-length and sunrise/sunset table for the year; cross-check with
  Open-Meteo hourly cloud cover for the claimed time ("was it overcast?"); sun-direction overlay on the map.
  Core maths implemented in Rust (no external data).
- Verified upstreams (optional): `https://archive-api.open-meteo.com/v1/archive?...&hourly=cloud_cover,temperature_2m`;
  `https://api.open-meteo.com/v1/forecast?...&current=...`; `https://api.sunrise-sunset.org/json?lat=..&lng=..&date=..&formatted=0` (cross-check only).
- Secrets: none.
- [system]: no.
- UI: map with draggable pin, date/time picker, sun-direction line, shadow-length input and candidate band, a table. Tools: `sun_position`, `sun_shadow`, `sun_candidates`.

**4.2 `osm-query` — OSM feature and geocoder helper** (grid: Geospatial)
- Features (Overpass Turbo, Nominatim, Photon): friendly query builder (feature presets such as towers, bridges,
  fuel stations, rail crossings, military sites within radius/bbox) compiled to Overpass QL with a raw-QL mode;
  geocode and reverse geocode; results on the map and as GeoJSON; recent OSM changesets and open map notes in the
  view (a "was this recently edited" check); distance filter between two feature types ("a bridge within 200 m of a
  rail crossing" geolocation pattern).
- Verified upstreams: `https://nominatim.openstreetmap.org/search?q=..&format=json` (1 request/s policy);
  `https://photon.komoot.io/api/?q=..`; `https://api.openstreetmap.org/api/0.6/changesets?bbox=..`;
  `https://api.openstreetmap.org/api/0.6/notes.json?bbox=..`.
  NOT verified: Overpass (`https://overpass-api.de/api/interpreter` returned 406 to all probes from this host). Make the base URL configurable via `[service.env]` (`OSNT_OVERPASS_URL`) and test from the Pi before building the presets.
- Secrets: none.
- [system]: no.
- UI: preset dropdown + query box + map; result table. Tools: `osm_find`, `osm_geocode`, `osm_reverse`, `osm_recent_edits`.

**4.3 `terrain-view` — Elevation, horizon and line of sight** (grid: Geospatial)
- Features (PeakFinder-style horizon matching, viewshed tools): elevation at a point; elevation profile along a line;
  line-of-sight between two points with Earth curvature and refraction; horizon silhouette (azimuth vs elevation angle)
  from a point, to compare against a photo's skyline; visible-from-here cone. Terrain via decoded Terrarium tiles
  (pure-Rust PNG decode, tile cache) so no whole datasets are stored.
- Verified upstreams: `https://api.open-meteo.com/v1/elevation?latitude=..&longitude=..`;
  `https://api.opentopodata.org/v1/srtm30m?locations=lat,lon`;
  `https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png` (HEAD verified, tile decode not tested).
- Secrets: none.
- [system]: no.
- UI: map click for observer, radius slider, canvas horizon chart, profile chart. Tools: `terrain_elevation`, `terrain_profile`, `terrain_los`, `terrain_horizon`.

**4.4 `place-photos` — Geotagged place photos** (grid: Geospatial)
- Features: Wikimedia Commons geosearch (photos of places and landmarks near a coordinate, with licence and author
  credit), Wikipedia geosearch for nearby articles, and with a token Mapillary street-level image coverage (image
  positions and capture dates). Purpose: compare a claimed location to what is there. Places only; faces are not
  analysed and results are not filterable by person.
- Verified upstreams: `https://commons.wikimedia.org/w/api.php?action=query&list=geosearch&gscoord=lat|lon&gsradius=..&gslimit=..&format=json`;
  `...prop=imageinfo&iiprop=extmetadata|url&titles=File:...` (verified).
  Mapillary `https://graph.mapillary.com/images` needs a token (500 OAuth error verified without); KartaView did not respond (unverified, omit).
- Secrets: `MAPILLARY_TOKEN` (optional).
- [system]: no.
- UI: map with photo markers, thumbnail strip, credit and licence line. Tools: `places_photos_near`, `places_articles_near`.

**4.5 `geo-toolkit` — Coordinates and geodesy** (grid: Geospatial)
- Features: coordinate parser/converter for decimal degrees, DMS, UTM, MGRS, geohash, Plus Codes; geodesic distance
  and bearing; destination point; circle/bbox/grid generator; GeoJSON paste/view/clean; KML/GPX/GeoJSON export; text
  scanner that finds coordinates in pasted text; timezone and UTC-offset from coordinates (embedded tz boundaries
  would be a large dataset, so use a lightweight lookup or skip; builder decides).
- Verified upstreams: none required (offline maths).
- Secrets: none.
- [system]: no.
- UI: paste box, format table, map preview. Tools: `geo_convert`, `geo_distance`, `geo_extract`.

### Batch 5: Events and news

**5.1 `gdelt-news` — Global news and event monitor** (grid: Events & News)
- Features: GDELT DOC 2.0 article search (query, language, source country, timespan) with timeline volume, tone
  timeline and top domains; latest 15-minute export list (`lastupdate.txt`) for event/GKG file pulls; "story
  tracker" that stores a few saved queries and flags volume spikes. Request spacing enforced: one upstream call per 5 seconds, shared queue.
- Verified upstreams: `https://api.gdeltproject.org/api/v2/doc/doc?query=..&mode=artlist&maxrecords=N&format=json` (works with a descriptive UA and 5 s spacing; HTTP 429 otherwise);
  `http://data.gdeltproject.org/gdeltv2/lastupdate.txt` (verified; follows a redirect).
  The `geo/geo` GeoJSON endpoint returned 404 and is not planned. `mode=timelinevol` hit the rate limit during testing so is not individually confirmed.
- Secrets: none.
- [system]: no.
- UI: query bar, article list, volume/tone chart, saved queries with spike badges. Tools: `gdelt_articles`, `gdelt_timeline`.

**5.2 `rss-watch` — Public feed monitor** (grid: Events & News)
- Features: poll RSS/Atom feeds (OPML import/export), dedupe, keyword and regex alerts with a "new since last visit"
  inbox, per-feed health, Hacker News Algolia keyword alert source, and opt-in public Telegram channel previews
  (`t.me/s/<channel>`, public channels only, no groups/members/users; fetch not verified). Feeds are stored in redb; all fetches pass the SSRF guard.
- Verified upstream: `https://hn.algolia.com/api/v1/search?query=..&tags=story&hitsPerPage=N`; GDACS and volcano RSS were verified as examples of working feeds.
- Secrets: none.
- [system]: no.
- UI: left feed list, centre article list with highlight of matched keywords, alert rules editor. Tools: `rss_inbox`, `rss_search`.

**5.3 `wiki-intel` — Wikipedia and Wikidata event watch** (grid: Events & News)
- Features: Wikipedia "On this day" and current events; page-view spike detector (pageviews API) for a list of
  topics; Wikimedia EventStreams `recentchange` filtered to watched articles (article-level change notices, no editor
  attribution or IP display); Wikidata entity facts (organisations, places, events, vessels, aircraft types).
- Verified upstreams: `https://en.wikipedia.org/api/rest_v1/feed/onthisday/events/MM/DD`;
  `https://stream.wikimedia.org/v2/stream/recentchange` (SSE handshake verified);
  `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=..&language=en&format=json`;
  `https://www.wikidata.org/w/api.php?action=wbgetentities&ids=Q..&props=claims&format=json`.
  Pageviews endpoint (`wikimedia.org/api/rest_v1/metrics/pageviews/...`) not tested.
- Secrets: none.
- [system]: no.
- UI: watchlist with sparkline per topic, event feed, entity card. Tools: `wiki_onthisday`, `wiki_pageviews`, `wikidata_entity`.

**5.4 `conflict-events` — Conflict event data** (grid: Events & News)
- Features: UCDP georeferenced events by country/date/violence type, ACLED events if a key exists; map and timeline
  filters; event-type breakdown; links to the dataset's own codebook. Terms of both services require attribution and
  disallow bulk redistribution; the plugin keeps only a short cache.
- Verified upstream: `https://ucdpapi.pcr.uu.se/api/gedevents/<version>?pagesize=N` (401 verified: header `x-ucdp-access-token` required).
  ACLED host did not respond from the research host: not verified.
- Secrets: `UCDP_ACCESS_TOKEN` (required for UCDP, free from UCDP), `ACLED_API_KEY` and `ACLED_EMAIL` (optional).
- [system]: no.
- UI: map with event clusters, date slider, side panel with event details. Tools: `conflict_events`.

### Batch 6: Hazards and disasters

**6.1 `quake-tsunami` — Earthquakes and tsunami messages** (grid: Hazards)
- Features: USGS 2.5+/4.5+/significant feeds and ComCat query by area/time, EMSC (euro-med) FDSN query, tsunami.gov
  bulletins (PTWC/NTWC Atom), magnitude/depth filters, "felt reports" count, event page deep links, historical
  query for an area (what shook here last week).
- Verified upstreams: `https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson`;
  `https://www.seismicportal.eu/fdsnws/event/1/query?limit=N&format=json`;
  `https://www.tsunami.gov/events/xml/PHEBAtom.xml`. (`fdsnws` query on USGS not individually tested; same host family.)
- Secrets: none.
- [system]: no.
- UI: map with magnitude circles, list with time-ago, tsunami banner. Tools: `quake_recent`, `quake_search`, `tsunami_bulletins`.

**6.2 `hazard-events` — Multi-hazard event aggregator** (grid: Hazards)
- Features: GDACS alert-levelled events (earthquake, cyclone, flood, volcano, drought, wildfire) with alert score and
  population exposure; NASA EONET open natural events by category; NWS active alerts by area; Smithsonian GVP weekly
  volcanic activity report; USGS HANS elevated volcanoes; NHC active storms; optional ReliefWeb v2 disaster
  records. One common event model and map.
- Verified upstreams: `https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH?eventlist=EQ;TC&alertlevel=Orange;Red`;
  `https://eonet.gsfc.nasa.gov/api/v3/events?limit=N&status=open`; `https://api.weather.gov/alerts/active?area=CA`
  (the `limit` parameter returns HTTP 400); `https://volcano.si.edu/news/WeeklyVolcanoRSS.xml`;
  `https://volcanoes.usgs.gov/hans-public/api/volcano/getCapElevated`; `https://www.nhc.noaa.gov/CurrentStorms.json`.
  ReliefWeb v2: 403 without an approved `appname` (v1 gone).
- Secrets: `RELIEFWEB_APPNAME` (optional).
- [system]: no.
- UI: map layers by hazard type, alert-level filters, event drawer. Tools: `hazards_active`, `hazards_near`, `hazards_alerts`.

**6.3 `fire-watch` — Active fire watch** (grid: Hazards)
- Features: FIRMS active-fire detections for an area/country/time window; cluster to "fire events", count and FRP
  (fire radiative power) statistics; day/night split; "area watches" that flag new clusters in a saved box; CSV/GeoJSON
  export. Extends the existing `imagery` plugin's thermal layer rather than duplicating it: it adds statistics and
  alerts, not imagery; builder should read `plugins/imagery/src` first and reuse its parsing where practical.
- Verified upstreams: `https://firms.modaps.eosdis.nasa.gov/data/active_fire/suomi-npp-viirs-c2/csv/SUOMI_VIIRS_C2_Global_24h.csv`
  (6 MB, no key). Area/country APIs `https://firms.modaps.eosdis.nasa.gov/api/area/csv/<MAP_KEY>/...` need a key (`DEMO_KEY` rejected HTTP 400).
- Secrets: `FIRMS_MAP_KEY` (optional; unlocks multi-day area queries).
- [system]: no.
- UI: map with cluster circles, stats cards, watch list. Tools: `fire_recent`, `fire_clusters`.

**6.4 `space-watch` — Launches and orbital objects** (grid: Hazards)
- Features: Launch Library 2 upcoming/previous launches with pad, provider, status and window; CelesTrak GP element
  sets by name/NORAD ID/group, SATCAT-style attributes (owner, launch date, decay), "recently launched" and "decaying
  soon" lists; map of launch sites. Passes are left to `doppler` and `satellite`; this plugin links to them.
- Verified upstreams: `https://ll.thespacedevs.com/2.2.0/launch/upcoming/?limit=N`;
  `https://celestrak.org/NORAD/elements/gp.php?CATNR=25544&FORMAT=json` (also `GROUP=` and `NAME=` forms by the same endpoint, not individually tested).
  DONKI space weather via `DEMO_KEY` did not respond (unverified, omit).
- Secrets: none.
- [system]: no.
- UI: launch schedule list with countdown, object search, pad map. Tools: `space_launches`, `space_object`, `space_recent`.

### Batch 7: Transport tracking (objects only)

**7.1 `ais-vessels` — Vessels by MMSI/IMO** (grid: Air & Sea)
- Features: live vessel positions and metadata from Finland's Digitraffic AIS (Baltic and Gulf of Finland, gzip
  required); vessel lookup by MMSI/IMO/name; recent track from stored points (short retention); optional AISStream.io
  global feed (WebSocket) and Global Fishing Watch events with free keys; "is this vessel on a sanctions list"
  button (calls `sanctions-screen`, `requires`). Vessels as objects only; no owner-individual lookups.
- Verified upstreams: `https://meri.digitraffic.fi/api/ais/v1/locations` and `.../vessels` (both 200 with `Accept-Encoding: gzip`, 406 without).
  AISStream handshake reached (`wss://stream.aisstream.io/v0/stream`, key required). Global Fishing Watch not tested.
- Secrets: `AISSTREAM_API_KEY`, `GFW_API_TOKEN` (both optional).
- [system]: no.
- UI: map with vessel icons and heading, side panel with vessel particulars, track line. Tools: `ais_near`, `ais_vessel`, `ais_track`.

**7.2 `rail-live` — Train movements** (grid: Air & Sea)
- Features: live trains and station boards from Digitraffic rail (Finland); Entur (Norway) GraphQL vehicle positions if
  it works for anonymous reads; OpenRailwayMap tile overlay on the map. Trains as objects only.
- Verified upstream: `https://rata.digitraffic.fi/api/v1/live-trains/station/HKI?departing_trains=1&arriving_trains=0&arrived_trains=0&departed_trains=0` (gzip needed).
  Entur `https://api.entur.io/realtime/v1/vehicles/graphql` returned 400 to an empty GET (needs a query, unverified). Deutsche Bahn `transport.rest` returned 503.
  OpenRailwayMap site reachable (tile path not tested).
- Secrets: none.
- [system]: no.
- UI: map with trains and stations, station board. Tools: `rail_station`, `rail_near`.

**7.3 `aircraft-registry` — Aircraft registry and routes** (grid: Air & Sea)
- Features: ICAO hex to registration, type, manufacturer and registered owner/operator (as listed by the database);
  callsign to route and airline; type designator lookups; airport info; optional OpenSky/adsb.lol position cross-check.
  Complements `adsb`, which already offers live search by hex/registration/callsign; this plugin adds the static
  registry and route data and exposes it as an API for `adsb`/`link-graph`. Builder must check `plugins/adsb/src/main.rs`
  first and avoid duplicating its live search. Registered owners of private aircraft can be individuals; the plugin
  returns operator/organisation names and hides personal-owner names (shows "private owner" only).
- Verified upstreams: `https://api.adsbdb.com/v0/aircraft/<hex>`; `https://api.adsbdb.com/v0/callsign/<callsign>`;
  `https://hexdb.io/api/v1/aircraft/<hex>`; `https://api.adsb.lol/v2/point/<lat>/<lon>/<nm>`; OpenSky `https://opensky-network.org/api/states/all?lamin=..` (anonymous, limited).
  airplanes.live returned HTTP 403 requiring a contact email; adsb.fi did not respond: both excluded.
- Secrets: none.
- [system]: no.
- UI: search by hex/reg/callsign, aircraft card, route map. Tools: `aircraft_by_hex`, `aircraft_route`.

**7.4 `maritime-notices` — Navigational and maritime safety warnings** (grid: Air & Sea)
- Features (NGA MSI): active navigational and broadcast warnings by NAVAREA and subregion (rocket debris areas,
  military exercises, hazards), ASAM piracy/hostile-act reports, World Port Index lookup; extracts coordinates from
  warning text and draws the polygons or points on the map (a classic OSINT trick for spotting exercises and launches).
- Verified upstream: `https://msi.nga.mil/api/publications/broadcast-warn?output=json&status=active` (200, 39 KB). ASAM and World Port Index endpoints share the host; paths not individually tested.
- Secrets: none.
- [system]: no.
- UI: list by NAVAREA with expandable text and the extracted shape on the map. Tools: `msi_warnings`, `msi_asam`.

### Batch 8: Media verification, archiving and the investigator's own notes

**8.1 `web-archive` — Web archives** (grid: Media & Verification)
- Features (gau, waybackurls, Auto Archiver): Wayback CDX query (snapshots per URL/domain, status, digest changes,
  first/last seen), side-by-side text diff of two snapshots, domain URL harvest (wildcard CDX), Common Crawl index
  lookups, Save Page Now request (rate limited; user-triggered only), "archive this and record the hash, time and
  archive URL" evidence record (sent to `case-notebook`). archive.today is link-out only.
- Verified upstreams: `https://web.archive.org/cdx/search/cdx?url=D&output=json&limit=N` (200);
  `https://web.archive.org/web/timemap/json?url=D&limit=N` (200); `https://index.commoncrawl.org/collinfo.json` (200).
  `https://archive.org/wayback/available` returned HTTP 429 under repeated tests (use CDX instead). `https://web.archive.org/save/<url>` returned a 302; behaviour of an anonymous capture is not verified.
- Secrets: `ARCHIVE_ORG_ACCESS` and `ARCHIVE_ORG_SECRET` (optional; higher Save Page Now limits).
- [system]: no.
- UI: URL box, calendar heatmap of snapshots, diff pane, evidence button. Tools: `archive_snapshots`, `archive_diff`, `archive_urls`.

**8.2 `media-verify` — Video and image verification helpers** (grid: Media & Verification)
- Features (InVID-WeVerify, C2PA): YouTube thumbnail frames (the four stock frames at `i.ytimg.com/vi/<id>/{0,1,2,3}.jpg`)
  with one-click reverse-search links; video keyframe extraction and metadata (container creation time, codecs, GPS
  tags) via ffmpeg/ffprobe when installed; frame magnifier and contrast/sharpen filters in the page; C2PA/Content
  Credentials manifest reader if a pure-Rust crate builds for musl (builder must confirm; otherwise omit). No face
  detection, no matching of people. Overlaps imgmeta/provenance by design only for links: it reuses `imgmeta`'s ELA through `requires`.
- Verified: nothing external required for stock frames beyond `i.ytimg.com` (not tested); C2PA feasibility not verified.
- Secrets: none.
- [system]: `ffmpeg` (optional; keyframes and ffprobe metadata), declared in `[system]` for approval. The plugin degrades to thumbnails and links without it.
- UI: upload or URL (SSRF-guarded), keyframe grid, metadata table, reverse-search link buttons. Tools: `media_probe`, `media_keyframes`.

**8.3 `case-notebook` — Investigation notebook and evidence log** (grid: Investigation)
- Features (Obsidian/Hunchly idea, Auto Archiver log): cases with Markdown notes, tags, a timeline of events with
  dates and sources, and an evidence log (URL, capture time, SHA-256 of a saved copy or screenshot, archive URL,
  note) with a tamper-evident hash chain; "pin this result" button other plugins can call to add an item to a case;
  export a case as a Markdown+JSON bundle. Stored in redb in `state_dir`. Access uses the hub gateway signature
  (`osnt_common::gateway_authorized`) for writes since notes can be private.
- Verified upstreams: none; local only. `provides = ["case-notebook"]`.
- Secrets: none.
- [system]: no.
- UI: left case list, centre note editor with preview, right evidence/timeline panels. Tools: `case_list`, `case_add_evidence`, `case_add_note` (add-only; the agent never reads private notes unprompted and cannot delete).

**8.4 `link-graph` — Entity link graph** (grid: Investigation)
- Features (Maltego-style, OpenCTI/Yeti ideas; Cytoscape.js or vis-network for the canvas, loaded from `/static` or vendored): nodes limited to domain, IP, ASN, certificate, organisation, URL, file hash, vessel, aircraft,
  place, event, note. Right-click "expand" runs transforms by calling other plugins (for example domain -> subdomains via
  `subdomain-enum`, IP -> ASN via `ip-intel`, organisation -> parent via `corp-registries`, vessel -> sanctions via
  `sanctions-screen`); force layout; pin and group; save/load graphs in redb; export GraphML, GEXF and Mermaid; import
  from `case-notebook` items. The node-type list has no person, username, email or phone type, and the import rejects them.
- Verified upstreams: none directly; uses sibling plugins (`requires` list: lookup, ip-intel, asn-bgp, subdomain-enum, corp-registries, sanctions-screen).
- Secrets: none.
- [system]: no.
- UI: full-screen canvas, node palette, transform menu, inspector, saved graph list. Tools: `graph_add_edge`, `graph_export`.

---

## 4. Port table (8130-8189, assigned in batch order)

All ports are free of every existing `plugin.toml` (checked: 8101-8107, 8110, 8111, 8120-8125, 8190; 8100/8108/8109 avoided).

| Port | Plugin id | Batch |
|---|---|---|
| 8130 | ip-intel | 1 |
| 8131 | asn-bgp | 1 |
| 8132 | subdomain-enum | 1 |
| 8133 | domain-hygiene | 1 |
| 8134 | cve-watch | 2 |
| 8135 | threat-feeds | 2 |
| 8136 | ioc-lookup | 2 |
| 8137 | cidr-exposure | 2 |
| 8138 | site-fingerprint | 2 |
| 8139 | sec-edgar | 3 |
| 8140 | sanctions-screen | 3 |
| 8141 | offshore-leaks | 3 |
| 8142 | corp-registries | 3 |
| 8143 | money-trail | 3 |
| 8144 | sun-shadow | 4 |
| 8145 | osm-query | 4 |
| 8146 | terrain-view | 4 |
| 8147 | place-photos | 4 |
| 8148 | geo-toolkit | 4 |
| 8149 | gdelt-news | 5 |
| 8150 | rss-watch | 5 |
| 8151 | wiki-intel | 5 |
| 8152 | conflict-events | 5 |
| 8153 | quake-tsunami | 6 |
| 8154 | hazard-events | 6 |
| 8155 | fire-watch | 6 |
| 8156 | space-watch | 6 |
| 8157 | ais-vessels | 7 |
| 8158 | rail-live | 7 |
| 8159 | aircraft-registry | 7 |
| 8160 | maritime-notices | 7 |
| 8161 | web-archive | 8 |
| 8162 | media-verify | 8 |
| 8163 | case-notebook | 8 |
| 8164 | link-graph | 8 |

Ports 8165-8189 stay free for follow-ups.

Id lengths are all 20 characters or fewer (longest: `aircraft-registry`, `sanctions-screen`, `subdomain-enum`, `maritime-notices` at 16-17).

---

## 5. Verification log and what could not be verified

Verified with a real request (HTTP 200 and the expected data), research host, 2026-11-02/03: Shodan InternetDB; USGS GeoJSON;
EMSC FDSN; GDACS; NASA EONET; GLEIF (`lei-records`, `fuzzycompletions`); SEC `data.sec.gov` submissions and XBRL concept,
`company_tickers.json` with a contact UA, browse-edgar Atom; Feodo Tracker; SSLBL; CISA KEV; NVD; EPSS; OSV; MITRE cveawg;
GitHub advisories; Shodan CVEDB; RIPEstat (prefix-overview, as-overview, asn-neighbours, whois, geolocation, abuse
contact, routing-history, bgp-state); PeeringDB; RIPE Atlas probes; ipwho.is; ipapi.co; Robtex; HackerTarget; OTX domain general;
GreyNoise community (404 for unseen IP is a normal answer); mnemonic passive DNS; Certspotter; dns.google DoH; OpenSanctions
bulk dataset files and index; OFAC SDN direct export; EU FSF CSV (HEAD); ICIJ reconcile manifest and query; Wikidata search, entities and
SPARQL; Nominatim; Photon; OSM changesets and notes; Open-Meteo (archive, forecast, elevation); OpenTopoData; Terrarium tile
(HEAD); sunrise-sunset.org; OpenSky anonymous; adsb.lol; hexdb; adsbdb; Digitraffic AIS and rail (gzip needed); NGA MSI; tsunami.gov Atom;
Smithsonian volcano RSS; USGS HANS; NHC CurrentStorms; NWS alerts (`area=CA`); FIRMS global 24 h CSV; Launch Library 2; CelesTrak GP;
USAspending; ProPublica nonprofits; Senate LDA (via redirect); TED v3; Norway Brreg; Czech ARES; Finland PRH; Denmark cvrapi;
Wikimedia (On this day, EventStreams SSE, Commons geosearch and imageinfo); Hacker News Algolia; Internet Archive CDX and
timemap; Common Crawl `collinfo`; Onionoo; Tor bulk exit list; Spamhaus DROP; ipsum; urlscan anonymous search; GDELT DOC (after
HTTP 429 backoff) and `lastupdate.txt`; SSL Labs `info`; Mozilla/other lookups listed below as failed.

Not verified or failing, with the observed behaviour (do not trust these until a builder retests):

- Overpass API: HTTP 406 from `overpass-api.de` (GET and POST) and no response from two other instances. The failure might be specific to this network. Retest from the Pi.
- abuse.ch URLhaus, ThreatFox, MalwareBazaar: anonymous exports return HTTP 410 and the API returns 401. A free Auth-Key is needed. Their current API paths were not confirmed (a search result described URL-path key support in a 2026 changelog from a mirror, which I did not verify).
- OpenSanctions API (`api.opensanctions.org`), OCCRP Aleph, OpenCorporates, Companies House, UCDP, Mapillary, FIRMS area API: return 401/400 without keys (as expected); not tested with keys.
- SEC EDGAR full-text search `efts.sec.gov`: HTTP 403 with and without a contact UA.
- ACLED API, KartaView, adsb.fi, BGPView, NASA DONKI (`DEMO_KEY`), `api.sunrise-sunset.org` is fine but `api.nasa.gov` requests did not respond: no response from the research host.
- GDELT `geo/geo`: HTTP 404. GDELT timeline modes: only rate-limited responses seen.
- ReliefWeb: v1 decommissioned (410); v2 needs an approved `appname` (403).
- airplanes.live: HTTP 403 asking for contact details. DB `transport.rest`: HTTP 503. Entur GraphQL: HTTP 400 for an empty GET.
- UN consolidated sanctions XML at `scsanctions.un.org/resources/xml/en/consolidated.xml`: HTTP 404 (use the OpenSanctions slice).
- Archive.org `wayback/available`: HTTP 429 under repeated requests; `save/` returned 302 (final behaviour unknown).
- OpenPhish `feed.txt`: HTTP 302 (final content unknown). CIRCL pDNS: 401. Anubis: 301.
- Licences not verified (stated as unverified in the table): Bellingcat toolkit sheet, InVID-WeVerify plugin, c2pa-rs, Overpass, Open-Meteo,
  Digitraffic, UCDP, OpenSanctions datasets, Wappalyzer/wappalyzergo, Exploit-DB, OpenCTI, ICIJ data terms.
- Rate limits listed as "per vendor docs, not tested" were taken from general knowledge of those vendors' published pages and were not
  checked against the live docs in this research pass.
- I read the plugin manifests and a grep of existing tool names, not the source of `adsb` or `imagery`; the overlap notes for
  `aircraft-registry` and `fire-watch` therefore tell the builder to read those first.

---

## 6. Verdict counts

Counted by script over the 131 numbered candidate rows (a row with a combined verdict counts once, by its leading verdict):

- BUILD: 41 rows (several map to the same plugin; 35 distinct plugins are planned)
- MERGE-INTO: 57 rows
- SKIP: 33 rows
- Declined (section 2, listed separately, not in the table): 16 groups of tools
