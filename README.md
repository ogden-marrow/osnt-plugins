# OSNT plugins

The plugin repository for [osnt-hub](https://github.com/ogden-marrow/osnt-hub), a modular open source intelligence
hub in Rust that runs on a Raspberry Pi. Each folder under `plugins/` is one plugin: a small, pure-Rust service plus
its web page. `index.toml` lists them so the hub can search and install by name.

## Install a plugin

From a machine with the hub's `osnt-deploy` tool (`cargo deploy ...` in the hub repo):

```bash
cargo deploy repo add https://github.com/ogden-marrow/osnt-plugins    # once: register this repository
cargo deploy plugin search                                            # list what is available
cargo deploy plugin add adsb                                          # install by id
cargo deploy plugin add https://github.com/ogden-marrow/osnt-plugins/tree/main/plugins/adsb   # or by folder link
cargo deploy plugin list
cargo deploy plugin remove adsb [--purge]
```

A folder link works for any public GitHub repository that follows the format below, so you do not need this repository
to share a plugin. The installer pins the link to an exact commit, shows what the plugin is allowed to do, and asks
before building. Plugins are third-party code: read the source before you install one.

## Layout

```
index.toml           plugin listing for search and install-by-id
sdk/                 osnt-common: the helper crate plugins depend on (HTTPS client, credential lookup)
plugins/<id>/
  plugin.toml        manifest + service settings (below)
  Cargo.toml         standalone crate named osnt-<id> (its own empty [workspace], so it builds from this folder)
  src/main.rs        the service: listens on 127.0.0.1:<port>, serves a page at / and an API under /api
  assets/            the page
```

### plugin.toml

```toml
id = "adsb"                      # a-z, 0-9, '-'; the crate must be named osnt-<id>
name = "Aircraft (ADS-B)"        # launcher card
description = "One sentence."
grid = "Air & Sea"               # launcher grid (created if new)
port = 8101                      # 8100-8999, unique on the Pi
version = "0.1.0"

[service]
state_dir = true                 # writable /var/lib/osnt-<id>
[service.env]                    # non-secret environment; {port} and {state_dir} are substituted
OSNT_ADSB_BIND = "127.0.0.1:{port}"

[[secret]]                       # credentials the plugin may read (managed on the portal's Credentials page)
name = "SERVICE_API_KEY"
label = "Service API key"
help_url = "https://example.com/keys"
required = false
```

The installer generates the systemd unit itself (sandboxed: dynamic user, read-only filesystem, private /tmp). A plugin
cannot choose its own command line, privileges or paths. In code, read a credential with
`osnt_common::secret("SERVICE_API_KEY")`; only the names declared above are handed to that plugin.

## Writing a plugin

Copy `plugins/example`, or open this repository in Claude Code: the `osnt-plugin` skill (`.claude/skills/`) knows the
rules, and `docs/PLUGIN_PROMPT.md` is a prompt template. To develop against a local checkout of the SDK instead of the
repository copy, the plugins already point at `../../sdk`.

Build one for the Pi: `cargo build --release --target aarch64-unknown-linux-musl --manifest-path plugins/<id>/Cargo.toml`.
Everything is pure Rust, so no C cross-toolchain is needed.
