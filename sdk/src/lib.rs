//! Helpers shared by OSNT plugins.

use std::{sync::Arc, time::Duration};

/// HTTP(S) client with pure-Rust TLS. `user_agent` should identify the plugin; upstreams are free community services.
pub fn http_agent(user_agent: &str) -> ureq::Agent {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(provider)
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent(user_agent)
        .build()
        .into()
}

/// Look up a credential by name (for example `DEEPSEEK_API_KEY`). An environment variable of the same name wins
/// (handy for local development); otherwise the credentials plugin is asked over loopback.
/// Blocking. Returns None when the credential is not set. Never log the returned value.
pub fn secret(name: &str) -> Option<String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
        return None;
    }
    if let Ok(v) = std::env::var(name) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let core = std::env::var("OSNT_CREDENTIALS").unwrap_or_else(|_| "127.0.0.1:8110".into());
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(3))).build().into();
    // The custom header means a plain GET smuggled through some other fetcher (SSRF) cannot read secrets.
    // Each plugin has its own token (set by the installer) and can only read the secrets its manifest declares.
    let token = std::env::var("OSNT_PLUGIN_TOKEN").ok()?;
    let mut res = agent.get(&format!("http://{core}/internal/secrets/{name}")).header("X-OSNT-Internal", "1").header("Authorization", &format!("Bearer {token}")).call().ok()?;
    let v: serde_json::Value = res.body_mut().read_json().ok()?;
    v["value"].as_str().map(str::to_owned)
}

/// Gateway trust: has the portal vouched for this request (the user is signed in)?
///
/// The portal adds `X-OSNT-Gateway: v1.<unix time>.<hmac>` to every request it proxies, signed with a key derived for
/// this plugin only (`OSNT_GATEWAY_KEY`, set by the installer). Pass the request's method, its path and query exactly
/// as the plugin receives them (for example `/api/credentials`), and the header value. Requests older than a minute
/// are rejected. A plugin that holds only its own key can verify requests but cannot forge requests to other plugins.
pub fn gateway_authorized(method: &str, path_and_query: &str, header_value: Option<&str>) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let (Some(h), Ok(key)) = (header_value, std::env::var("OSNT_GATEWAY_KEY")) else { return false };
    let mut parts = h.splitn(3, '.');
    let (Some("v1"), Some(ts), Some(sig)) = (parts.next(), parts.next(), parts.next()) else { return false };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let Ok(ts_n) = ts.parse::<u64>() else { return false };
    if now.abs_diff(ts_n) > 60 {
        return false;
    }
    let Ok(sig_bytes) = (0..sig.len()).step_by(2).map(|i| u8::from_str_radix(sig.get(i..i + 2).unwrap_or("zz"), 16)).collect::<Result<Vec<u8>, _>>() else { return false };
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("hmac accepts any key length");
    mac.update(format!("{ts}.{method}.{path_and_query}").as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}
