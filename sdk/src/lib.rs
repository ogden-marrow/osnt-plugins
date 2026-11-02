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
