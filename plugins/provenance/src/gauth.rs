//! Google service-account sign-in, so the Vision credential can be the downloaded key file (JSON) instead of an API key.
//!
//! The JWT is signed with the account's private key (RS256) and exchanged for a short-lived access token at Google's
//! fixed token endpoint. The `token_uri` inside the key file is never followed, so a doctored file cannot redirect
//! the signed assertion elsewhere. Tokens are cached until shortly before they expire.

use std::{sync::Mutex, time::{SystemTime, UNIX_EPOCH}};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPrivateKey, pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, signature::{SignatureEncoding, Signer}};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;

pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// (client_email, access token, expiry as unix seconds)
static CACHE: Mutex<Option<(String, String, u64)>> = Mutex::new(None);

#[derive(Deserialize)]
struct Account {
    #[serde(rename = "type")]
    kind: String,
    client_email: String,
    private_key: String,
}

/// A credential value that is a key file rather than a plain API key.
pub fn is_service_account(value: &str) -> bool {
    value.trim_start().starts_with('{')
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn assertion(a: &Account, audience: &str, iat: u64) -> Result<String, String> {
    let key = RsaPrivateKey::from_pkcs8_pem(&a.private_key).map_err(|_| "the key file's private_key could not be read".to_string())?;
    let claims = json!({ "iss": a.client_email, "scope": SCOPE, "aud": audience, "iat": iat, "exp": iat + 3600 });
    let signing_input = format!("{}.{}", b64(br#"{"alg":"RS256","typ":"JWT"}"#), b64(claims.to_string().as_bytes()));
    let sig = SigningKey::<Sha256>::new(key).sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64(&sig.to_bytes())))
}

/// A bearer token for the service account in `key_file` (the JSON text). Blocking.
pub fn access_token(agent: &ureq::Agent, token_url: &str, key_file: &str) -> Result<String, String> {
    let a: Account = serde_json::from_str(key_file).map_err(|_| "the credential looks like JSON but is not a valid service-account key file".to_string())?;
    if a.kind != "service_account" {
        return Err("the JSON key file is not a service account key (type must be service_account)".into());
    }
    if let Some((email, token, exp)) = CACHE.lock().unwrap().as_ref() {
        if *email == a.client_email && *exp > now() + 60 {
            return Ok(token.clone());
        }
    }
    let jwt = assertion(&a, token_url, now())?;
    let body = format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={jwt}");
    let mut res = agent
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .config()
        .http_status_as_error(false)
        .build()
        .send(body.as_str())
        .map_err(|e| format!("could not reach Google sign-in: {e}"))?;
    let status = res.status().as_u16();
    let text = res.body_mut().with_config().limit(64 * 1024).read_to_string().unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    match v["access_token"].as_str() {
        Some(t) if status == 200 => {
            let exp = now() + v["expires_in"].as_u64().unwrap_or(3000);
            *CACHE.lock().unwrap() = Some((a.client_email, t.to_string(), exp));
            Ok(t.to_string())
        }
        _ => Err(format!(
            "Google rejected the service account (HTTP {status}: {}). Check that the key is still active and that the Cloud Vision API is enabled in its project",
            v["error_description"].as_str().or(v["error"].as_str()).unwrap_or("no details")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{pkcs1v15::VerifyingKey, signature::Verifier};

    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCgzRboDNqjHR53\nhb3TcPkY4H+Cg3ibQZ7BNF0yKSWXuV/GH/DOsowZLYSUptOoEl65lovelq5yadJw\n1JTP5V9Iho/euTR/CfhIC4DWGct/XgcQccSzUoz9A9sfiw/mYZ4tTv103OA1FUYY\n60//R9oBp7Knkjk4Ohsa4wDkisirkNELIotnZafGsJEubVbGInWDS5JtzjikOORZ\nR7uk7jSrUDwEh0PeZ0k3o0yXjyc2eo01T06IfpJmbgOOU+KAK2Hn7wg8T+xcfBTq\nYf1swL938d6ylpd+f5BV2M63m72xGA15veoMD1NqA/w4rs/MZu/AICx1+29oPo9o\nY00sTggtAgMBAAECggEAElVPt0U/6Dj5sEbfTawjumJeJ1M1/P2OTBjcR0vJrXLF\nKKGbovVYY8Z8xzX+C7uMcTxo1gf3+7N0+shB7zIHmw08efhDs/g/BnfJSJ/IQ81E\noOtXsdpHmNFHumDwfyPCFQhcfWZxaZvzUgQCKujWQjoMdG6Hd5GoZXhcMbJhDq5V\n4tC8LAACEygAQlNQAqKhJU8NzrrZ+dcAEuyEsLcwmOC8ZhWncV/NPHQR5/mkU5e0\n0ZbEpPmQw+FrGKugJ8UWyhAwu72oaj8fNxqzX7v6PFcm6rpNAE3r3TugBSMkAdzK\nDB1ZT/4tOk+Q+mCRpJlHJulMmHMhH2/8PCuJFQdjQQKBgQDMwgDAWnZleybhCczH\nLn5uAfAiXiYAA3Ds62/MLsqijwSUIUZx4zXgTO1zsCLQ0jz/6q0+9PytIQwYBGmL\nkgOMZWCa376IKeQsgULTw1zdwWZFVTqAG++l9TYb5eO3EroAEgS/R+H9lXgoKPPq\np1iKKEnOK7ttGZ1qE27iWKNppwKBgQDJCvX5NaF7vtvMS2zztJqUqepn6hWPFGnj\nWsYh/SHhmCN1OLLtJkBCH9bLVcKHRjn5gz8sxoypm18214bRDt3hDQG5JlpuV5yE\nbbcyn4uOpyYS/wf0fIAmS4xRN5Jvsp9tCBYr9CkLiQHZM9tfwo7RB6aOeE57XfDH\nuY26SydSCwKBgQDJqWDYEcB93jbCeMZofdAjRGFfV96RMNJtZMvtC0CjrbvSsJsS\n27ZaPSm4QQdpJ0bQvi72zI53bQ7eMKpKvfokskvc/PRIYwnJE13f9o9mEG5LZs+B\nEQKMLt+lxlrqGdV68EQgqAlZmXaIBx2ERGEdYOSf285ye0HgEVeqMaZwDQKBgA0B\nuIg3AAuRfYbqGlJqDNYxaAjxDBQFrhQXe1oXlmmR/jlHQcw1/VJJ3QuqsLsvv/B0\nnVG4RsFyW+agawh7fb9hqArigFdDM80djAyqZc0E42G3PjyDEYdou9tFTSQM2mOj\nckvFsCIe6w+yWy8G11aOuCffgLRaj4lcZ971ncWhAoGBAKscJ0ABsRL4oiPFas/7\nSJ5Z2VdtaWbdOrTdNAuFyuGEP6+Kl8XrHSl9r/GNi+gzgrL0vmjsxlRUT3dKZs4b\nQj+bkVyHOmXKISQiarxHfoNCwwkXGvug3g1YrJeHc1XuqrMFI3JM7M89jfCBGSZV\n7MxHODMLdYBJskqkQckJHjBo\n-----END PRIVATE KEY-----";

    fn account() -> Account {
        Account { kind: "service_account".into(), client_email: "svc@proj.iam.gserviceaccount.com".into(), private_key: TEST_KEY.into() }
    }

    #[test]
    fn detects_key_files() {
        assert!(is_service_account("  {\"type\":\"service_account\"}"));
        assert!(!is_service_account("AIzaSyExample"));
    }

    #[test]
    fn assertion_is_a_valid_rs256_jwt() {
        let jwt = assertion(&account(), TOKEN_URL, 1_000).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "svc@proj.iam.gserviceaccount.com");
        assert_eq!(claims["aud"], TOKEN_URL);
        assert_eq!(claims["exp"], 4_600);
        let key = RsaPrivateKey::from_pkcs8_pem(TEST_KEY).unwrap();
        let verifier = VerifyingKey::<Sha256>::new(key.to_public_key());
        let sig = rsa::pkcs1v15::Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
        verifier.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).expect("signature verifies");
    }

    #[test]
    fn bad_files_are_refused_without_echoing_them() {
        let agent = osnt_common::http_agent("test");
        let e = access_token(&agent, TOKEN_URL, "{\"type\":\"authorized_user\",\"client_email\":\"a\",\"private_key\":\"SECRET-PK\"}").unwrap_err();
        assert!(e.contains("not a service account") && !e.contains("SECRET-PK"));
        let e = access_token(&agent, TOKEN_URL, "{not json SECRET-PK").unwrap_err();
        assert!(!e.contains("SECRET-PK"));
    }
}
