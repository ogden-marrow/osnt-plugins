# adsb-history

Historical ADS-B for OSNT without keeping a global archive. Given a UTC day, a time window (up to 6 h) and an optional
bounding box, ICAO hex list or callsign prefix, the plugin downloads only the part of adsb.lol's daily archive it needs
(streaming and filtering while downloading), stores a compact short-lived slice, and serves it over HTTP. Other plugins
declare `requires = ["adsb-history"]` and call `http://127.0.0.1:8120/api/...` over loopback; the browser uses the page
at `/p/adsb-history/`. Port 8120, `provides = ["adsb-history"]`.

## What the real archive looks like (researched 2026-11-02)

- Source: the `adsblol/globe_history_YYYY` GitHub repositories (2023 to 2026; 2023-2025 are archived, 2026 is live),
  one **release per day** and variant, licence ODbL 1.0 (the plugin credits "adsb.lol" in `/api/info`).
  Tag: `vYYYY.MM.DD-planes-readsb-{prod,staging,mlatonly}-0`. `prod` is the normal feed. The current UTC day only has a
  `staging` release (it is replaced by `prod` after the day ends), so the plugin tries prod and falls back to staging.
- Asset: **one uncompressed GNU tar**, published as 2 GB parts `...tar.aa`, `...tar.ab` (about 3.1-3.3 GB for a day in
  2025-2026; 2023-2024 days are a single 1.4-1.7 GB `.tar`; mlatonly is 0.1-0.7 GB). Concatenate the parts to get the tar.
  `https://github.com/adsblol/globe_history_2026/releases/download/v2026.11.01-planes-readsb-prod-0/v2026.11.01-planes-readsb-prod-0.tar.aa`
- **HTTP range requests work.** github.com answers 302 to a signed `release-assets.githubusercontent.com` URL (valid
  about 1 h) which returns `206` with `Accept-Ranges: bytes`. Streaming a member is therefore one Range request.
- The tar has **no index**, and the member order differs per day (readdir order): `heatmap/` came first on 2025-12-30,
  after `README`/`LICENSE`/`acas/` on 2024-06-15, and **after the ~2.4 GB of `traces/` on 2026-11-01**.
- Contents: `heatmap/NN.bin.ttf` (NN = 00..47, one per UTC half hour, 8-22 MB each, ~0.7 GB total, in scrambled order),
  `traces/xx/trace_full_<hex>.json` (per-aircraft full-resolution traces, tens of thousands of tiny gzip files, the bulk
  of the tar), `acas/`, licences.
- **`heatmap` format** (from readsb `globe_index.c`, verified on real files): each file is a gzip stream of 16-byte little
  endian entries `i32 hex, i32 lat, i32 lon, i16 alt, i16 gs`. An index of 180 entries, then for each 10-second slice a
  marker (`hex = 0xe7f7c9d`, lat/lon = high/low 32 bits of unix ms) followed by that slice's entries: positions (lat/lon in
  1e-6 deg, alt in 25 ft steps, -123 = ground, -124 = unknown, gs in 0.1 kt) and callsign/squawk entries (`lat >= 2^30`).
  So the heatmap is **every aircraft the network heard, one point per aircraft per 10 s, worldwide** (~550k positions
  per half hour). That is the resolution this plugin serves.

## How a window is fetched

1. Locate the day's archive (probe the part sizes with `Range: bytes=0-0`; only `github.com` and
   `*.githubusercontent.com` are ever contacted, the caller only supplies a validated date).
2. Find the needed `heatmap/NN.bin.ttf` members: hop tar headers with 512-byte Range requests (checksum-verified). If the
   tar starts with `traces/`, bisect for the end of the traces region with 1 MB probes (about 12 probes, ~12 MB) and hop
   from there. The offsets (a ~1 KB JSON per day) are cached, so this happens once per day.
3. For each half hour in the window, one Range request streams the member through a gzip decoder and a record parser;
   records are filtered (time, bbox incl. antimeridian, hex, callsign prefix, sampling step) as they arrive. Streaming
   stops as soon as the window ends, so a 5-minute window costs a fraction of a file (observed: 4.9 MB for 10 minutes).
   Nothing from the tar is ever written to disk.
4. Matching points are sorted per aircraft and written as one compact binary slice (20 bytes per point, ~22 bytes with
   metadata; 5,000 points = 110 KB).

Politeness: a descriptive User-Agent, one download at a time (a semaphore), 150 ms between header hops, 500 ms between
files, a per-job download budget (default 400 MB), a window cap (6 h) and a point cap (1.5 M, the slice is marked
`truncated`).

### What this cannot do

- **Resolution is the heatmap's 10 s**, not the sub-second/adaptive traces. The full `traces/` files are inside the tar
  with no index: finding one aircraft's trace means scanning ~2.5 GB, so full-resolution per-aircraft traces are not
  offered. (A future "deep" mode could stream the whole tar once, but that is exactly the multi-GB download this plugin
  avoids.)
- Callsign filtering only matches an aircraft once its callsign record has been seen in the stream (records appear
  just before the first position of each half hour, so occasionally the first sample is missed).
- A bbox/callsign query over a busy area for a long time is limited by the download budget; each half hour is a 8-22 MB
  download no matter how small the box is (the archive cannot be filtered server side).
- The newest day is only a `staging` release and may be incomplete.

## Cleanup

State dir (`/var/lib/osnt-adsb-history`): `slices/` (the data), `index/` (tar offsets), `tmp/` (half-written files).
- Slices expire after `OSNT_ADSB_HISTORY_TTL_HOURS` (default 6) without being read (reads refresh the timer); index
  files after max(TTL, 24 h). The whole slice cache is capped at `OSNT_ADSB_HISTORY_CACHE_MB` (300), oldest first.
- At startup `tmp/` is emptied, stray non-slice files are removed, then TTL and the cap are applied; a janitor repeats
  every 5 minutes. Temp files are removed on every error path (guard object), and writes are tmp + rename.

## API (all GET unless noted; paths are relative to the plugin root)

| Endpoint | |
|---|---|
| `api/slices?date=YYYY-MM-DD&from=HH:MM&to=HH:MM[&bbox=W,S,E,N][&hex=a,b][&callsign=UAL][&step=10..3600][&wait=secs]` | Start or reuse a fetch job (same params = same id, so concurrent callers share it). `200` + `ready:true` if available (or becomes available within `wait`, max 120 s), `202` while running, `502` with `error` if it failed, `400` for bad input. With no `date` it lists cached slices. |
| `api/jobs/{id}` | Progress: `state` queued/running/done/failed/cancelled, `phase`, `halfhours_done/total`, `bytes_downloaded`, `points`. `DELETE` cancels. |
| `api/slices/{id}/tracks[?hex=][&callsign=][&format=geojson]` | Positions per aircraft: `{"aircraft":[{"hex","callsign","squawk","points":[[unix_s,lat,lon,alt_ft\|"ground"\|null,gs_kt\|null],...]}]}`; `geojson` gives LineString features with parallel `times`, `alt_ft`, `gs_kt` arrays. |
| `DELETE api/slices/{id}` | Drop a slice now. |
| `api/info` | Limits, disk use, source credit. |
| `tools` | Agent tool definitions: `adsb_history_fetch`, `adsb_history_job`, `adsb_history_tracks`. |

All times are UTC. Example from a real run (10 minutes over Florida, 159 aircraft, 5,098 points, 4.9 MB downloaded, 15 s):
`curl '127.0.0.1:8120/api/slices?date=2026-11-01&from=12:00&to=12:10&bbox=-83,27,-80,31&wait=60'`.

The API is unauthenticated on loopback by design (callers are other plugins); it exposes only public data and triggers
only bounded, rate-limited downloads from fixed hosts.

## Tests

`cargo test` runs against a fake GitHub-release server serving fixture tars (split into parts, redirecting to a blob host,
honouring Range, both tar layouts), covering parsing, filtering, caching, the traces-first bisect, the download budget,
validation and cleanup. Pi build: `cargo build --release --target aarch64-unknown-linux-musl` (needs the repo's
`rust-lld` linker config).
