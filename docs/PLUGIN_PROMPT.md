# Prompt template: add a plugin to OSNT

Paste this into a coding agent (Claude Code, etc.) opened in the repo root. Fill in the `<...>` parts.
Keep the "Context" and "Done when" sections as they are; they are what makes plugins come out consistent.

---

Add a new OSNT plugin called `<id>` (display name "<Name>", launcher grid "<Grid>").

## What it does
<One or two paragraphs: the data source or task, who uses it, and what the page should show.
Give example URLs/APIs verbatim, including any rate limits or usage policy you know of.>

## Operations the agent layer should be able to call
<List each as: name, one-line description, inputs, output shape. These become `GET /tools` entries.>

## Data and secrets
<Does it need to persist anything (history, cache)? For how long? Any API keys (name the env vars; never commit values)?>

## Context (read before writing code)
- Read `docs/PLUGINS.md` and copy `crates/example`; `crates/adsb` is a fuller reference (poller, redb storage, caching, map page).
- Pure Rust only: the Pi build uses `rust-lld` with no C toolchain. Use `ureq` + rustls RustCrypto for HTTPS and `redb` for storage, as `crates/adsb` does.
- Listen on `127.0.0.1:<port>` (pick an unused port); use relative URLs in the page; reuse `/static/osnt-map.js` for maps.
- Be polite to upstream services: cache responses, set a User-Agent, and respect their terms.
- Wire it in per section 2 of `docs/PLUGINS.md`: workspace member, `deploy/plugins.d/<id>.toml`, `deploy/osnt-<id>.service`, entry in `COMPONENTS`.

## Done when
1. `cargo build --release -p osnt-<id> --target aarch64-unknown-linux-musl` succeeds.
2. Run locally and hit each API endpoint with real data; show the output.
3. `cargo deploy <id>` succeeds, the card shows "open" on the launcher, and the page works through `/p/<id>/` on the Pi.
4. `GET /tools` lists every operation above.
5. Update the README layout list; commit.

---

## Tips for good results
- Say what "good" looks like for the page (a map? a table? alerts?) and what should happen when the upstream is down.
- Name the failure modes you care about (empty results, rate limits, bad input) so they get handled instead of guessed at.
- One plugin per prompt. If it needs a shared change to the core (a new layer kind, a new launcher feature), say so explicitly and keep that change separate.
