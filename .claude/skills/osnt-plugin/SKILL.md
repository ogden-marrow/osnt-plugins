---
name: osnt-plugin
description: Write, test and install a plugin for the OSNT hub (a Rust service folder in this repository, run on a Raspberry Pi behind the hub's portal). Use when asked to add, build or change a plugin, a launcher card, an OSINT data source, an API a plugin vends, or an agent-callable tool.
---

# Writing an OSNT plugin

A plugin is a standalone pure-Rust service in `plugins/<id>/`. The hub (a separate repository, `osnt-hub`) reads its
manifest, reverse-proxies `/p/<id>/` to it, adds a launcher card and exposes its `/tools` to agents.
Format reference: this repository's `README.md`. Prompt template: `docs/PLUGIN_PROMPT.md`.

## Start from the right reference
- `plugins/example`: minimal skeleton (page, one API route, `/tools`). Copy it first.
- `plugins/adsb`: poller, caching, redb storage, map page, alerts.
- `plugins/lookup`, `imgmeta`, `cameras`, `imagery`, `map`: small real plugins (JSON lookups, uploads, config-driven feeds, frontend-only).
- `plugins/provenance`: agent loop with an LLM, SSRF-guarded fetching, declared secrets.
- `plugins/credentials`: the secret store (system plugin). `sdk/`: `osnt-common` (HTTPS client, `secret()`).

## Rules
1. Listen on `127.0.0.1:<port>` only; port in 8100-8999, unique (see `index.toml`/other `plugin.toml` files; credentials 8110, example 8190).
2. Pure Rust only: the Pi build uses `rust-lld`, there is no C toolchain (no `ring`, `aws-lc`, `openssl`, bundled SQLite). HTTPS goes through `osnt_common::http_agent()`; storage uses `redb`.
3. The crate is named `osnt-<id>`, has its own empty `[workspace]` table and its own `Cargo.lock`, and depends on the SDK with `path = "../../sdk"`.
4. Pages use relative URLs (`fetch('api/x')`); the hub mounts them at `/p/<id>/`. Shared assets are absolute: `/static/leaflet/leaflet.js`, `/static/osnt-map.js` (`await OSNT.createMap('map')`).
5. Serve `GET /tools` (JSON array of `{ name, description, method: "GET", path, parameters }`, `{param}` in `path` is substituted). Return `[]` if there is nothing safe for an agent to call. Never expose credentials or destructive actions to agents.
6. Never let callers supply arbitrary upstream hosts (SSRF). Validate inputs; fetch only fixed hosts or config. If a plugin fetches user-supplied URLs, copy the guard in `plugins/provenance/src/ssrf.rs`.
7. Declare credentials as `[[secret]]` in `plugin.toml` and read them with `osnt_common::secret("NAME")` (blocking; use `spawn_blocking`). Never log, return or put a secret in an error. If it is missing, degrade gracefully and point the user at the Credentials page.
8. A plugin that calls another plugin's API lists it in `requires`; one that vends an API lists it in `provides`.
9. Cache upstream calls and set a User-Agent; most upstreams are free community services.
10. Do not build features that identify people from images, audio or video (face recognition, matching individuals). Counting, non-identifying detection, metadata and provenance checks are fine.

## Add a plugin
1. `cp -r plugins/example plugins/<id>`, rename the crate to `osnt-<id>`, write `plugin.toml` (id, name, description, grid, port, version, `[service]`, `[[secret]]`).
2. Add it to `index.toml`.
3. Build for the Pi: `cargo build --release --target aarch64-unknown-linux-musl --manifest-path plugins/<id>/Cargo.toml` (must pass with no C compiler).
4. Run it locally and call every endpoint against real data; show the output.
5. Install on the Pi from the hub repository: `cargo deploy plugin add <path-to>/plugins/<id>`; confirm the card says "open", the page works at `/p/<id>/` and `/api/agent/tools` lists its tools.
6. Look at the page in a browser before saying it works. Commit with a message that says what the plugin does.
