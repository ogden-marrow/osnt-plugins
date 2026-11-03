# satellite

Map-first STAC search for free satellite scenes. Pick a sensor, dates and cloud limit, move the map to an area and press
Search. Scenes show as footprints and thumbnails; **Show** draws the scene on the map; **Set A** / **Set B** compares two
scenes with a swipe or blend slider.

- Sensors: Sentinel-2 L2A (10 m), Sentinel-1 SAR (10 m, works through cloud and at night), Landsat 8/9 (30 m), NAIP (0.6 m, US).
- Sources: Microsoft Planetary Computer (default; map tiles for every sensor, including radar) and Element 84 Earth Search
  (metadata; Sentinel-2 and NAIP drawn through titiler.xyz).
- No secrets needed. Optional secret `PC_SDK_SUBSCRIPTION_KEY` (free Planetary Computer key) is sent with STAC searches to raise limits.
- Agent tools (`/tools`): `satellite_search` (bbox, dates, kind, cloud, source -> scene metadata and links, no image bytes), `satellite_sources`.
- Env: `OSNT_SATELLITE_BIND`, `OSNT_SATELLITE_STATE` (cache under `<state>/cache`, 8 MB cap, 10 minute TTL). `OSNT_SATELLITE_PC_STAC`, `_ES_STAC`, `_PC_DATA`, `_TITILER` override upstreams (used by the tests).
- Tests: `cargo test` (fake STAC upstream, no internet).

Reading Sentinel-1: dark = smooth (calm water, tarmac), bright = rough or metal (ships, buildings), the default colour mix is VV/VH.
Radar is not a photograph and geometry is distorted on slopes.

## Research: free satellite imagery sources for OSINT (checked 2026-11-02)

Ranked by usefulness to this hub. "Verified" means I made a small real request on the date above.

| # | Source | What it gives | Access (verified) | Terms / attribution |
|---|--------|---------------|-------------------|---------------------|
| 1 | **Microsoft Planetary Computer** STAC + data API | Sentinel-2 L2A (10 m, ~5 d), Sentinel-1 RTC radar (10 m, day/night/cloud), Landsat C2 L2 (30 m), NAIP (0.6 m, US), HLS, NICFI tropics (collection listed, not exercised). Items carry `tilejson` and `rendered_preview` assets, so any scene is a slippy-map layer with no local tiler. Latency: hours (S1/S2 same day). | `POST https://planetarycomputer.microsoft.com/api/stac/v1/search` and `.../api/data/v1/item/tiles/WebMercatorQuad/{z}/{x}/{y}@1x.png?...` both worked with no key; tiles send `access-control-allow-origin: *`. A free subscription key is optional and only lifts rate limits (per the SDK docs; limits themselves not verified). | Data licences differ per collection (Sentinel: free/open, "Contains modified Copernicus Sentinel data"; Landsat/NAIP: public domain). Microsoft's terms of use for the API were not retrievable, so treat heavy automated use as unverified. |
| 2 | **Element 84 Earth Search** (AWS) | Open STAC for Sentinel-2 L2A/L1C, Sentinel-1 GRD, Landsat C2, NAIP, Copernicus DEM. | `POST https://earth-search.aws.element84.com/v1/search` worked, no auth, CORS `*`. Sort field must be `properties.datetime`. Sentinel-2 `thumbnail` and `visual` (TCI COG) are public HTTPS; Sentinel-1 and Landsat assets are `s3://` requester-pays, so only metadata is usable. | Same upstream licences. No stated rate limit; be polite. |
| 3 | **Esri World Imagery Wayback** | 198 dated releases, 2014-02-20 to 2026-10-29, of the world basemap (sub-metre in cities). Pre-rendered XYZ tiles, a per-tile "tilemap" index that tells which releases truly differ, and per-point capture-date/resolution metadata layers. | Release list `https://s3-us-west-2.amazonaws.com/config.maptiles.arcgis.com/waybackconfig.json`; tiles `https://wayback.maptiles.arcgis.com/arcgis/rest/services/world_imagery/wmts/1.0.0/default028mm/mapserver/tile/{release}/{z}/{y}/{x}` (the mixed-case path 301-redirects; use lowercase); tilemap `.../World_Imagery/MapServer/tilemap/{release}/{z}/{row}/{col}`; metadata `https://metadata.maptiles.arcgis.com/.../World_Imagery_Metadata_2026_r10/MapServer/{layer}/query`. All worked with no key, tiles CORS `*`. | Esri's Wayback terms page returned 404 and were not verified. Credit "Esri, Vantor, Earthstar Geographics and the GIS user community". Releases are basemap snapshots; the picture can be older than the date, so use the capture-date lookup. |
| 4 | **Maxar Open Data** (now Vantor branding) | 30-50 cm event imagery for disasters and crises: 55 events listed, pre- and post-event acquisitions, COGs plus cloud masks. | Static STAC `https://maxar-opendata.s3.amazonaws.com/events/catalog.json` (no auth); COGs are public over HTTPS. No tiler of their own: rendered through the public `titiler.xyz` (verified, a 256 px tile in ~1 s). | CC BY-NC 4.0: non-commercial, attribute Maxar. `titiler.xyz` is a community demo service with no stated SLA or usage policy (unverified); self-host a titiler if this becomes load-bearing. |
| 5 | **NASA GIBS / Worldview** | Daily MODIS/VIIRS true colour (250-375 m), VIIRS fires, nightlights (`VIIRS_Night_Lights` tile verified), aerosols, SST and 1,000+ layers; WMTS XYZ, no key, latency about a day. | Already covered by the `imagery` plugin (do not duplicate). | Public domain; credit NASA GIBS/EOSDIS. |
| 6 | **Copernicus Data Space (CDSE)** | Official Sentinel archive with STAC `https://stac.dataspace.copernicus.eu/v1`. Anonymous `POST /search` for `sentinel-2-l2a` worked. Previews, tiles (Sentinel Hub) and downloads need a free OAuth account, with quotas I did not verify. | Search: none. Everything else: OAuth. | Not built: PC and Earth Search give the same Sentinel data with tiles and no account. Best choice if you later want the 6-hour-fresh Sentinel-1 or the full Level-1 archive. |
| 7 | **EOX Sentinel-2 cloudless** | Annual cloud-free Sentinel-2 mosaic basemap (10 m), pre-rendered WMTS (`https://tiles.maps.eox.at/wmts/1.0.0/s2cloudless-2024_3857/default/g/{z}/{y}/{x}.jpg` returned a JPEG). | None. | CC BY-NC (from their site, not re-verified here). A nice background layer for the hub's `layers.toml`, not a plugin. |
| 8 | Landsat direct (USGS EarthExplorer/M2M) | Same data as in 1 and 2. | M2M API needs a login, so not used. | Public domain. |
| 9 | Planet NICFI (via PC) | Monthly 4.77 m tropical mosaics 2015-2020+; the program's free tier changed, so currency was not verified. | PC collection `planet-nicfi-visual` exists. | Licence "other"; check before use. Not wired into the UI. |
| 10 | Global Fishing Watch and similar | Satellite-derived vessel/event data, not imagery. | Skipped on purpose. | - |

Design consequence: no heavy tile server on the Pi. The plugins only relay small STAC/JSON responses (cached on disk for minutes to hours, size-capped); the browser pulls tiles directly from the upstream tilers.
