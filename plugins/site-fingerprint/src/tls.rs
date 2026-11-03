//! Read the TLS handshake of the final host: negotiated version, cipher, ALPN and the certificate chain.
//! The handshake accepts any certificate (so expired or self-signed sites can still be inspected) but records
//! whether the chain would have been trusted by the Mozilla root set. No application data is sent.

use std::{
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned,
    client::{WebPkiServerVerifier, danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier}},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_parser::{prelude::*, public_key::PublicKey};

use crate::common::{unix_now, ymd};

#[derive(Debug)]
struct Capture {
    inner: Arc<WebPkiServerVerifier>,
    error: Mutex<Option<String>>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        if let Err(e) = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn fmt_time(ts: i64) -> String {
    let t = ts.max(0) as u64;
    format!("{}T{:02}:{:02}:{:02}Z", ymd(t), (t % 86_400) / 3600, (t % 3600) / 60, t % 60)
}

fn sig_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.113549.1.1.10" => "RSASSA-PSS".into(),
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption (weak)".into(),
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption (weak)".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.3.101.112" => "Ed25519".into(),
        o => o.to_string(),
    }
}

/// Describe one DER certificate. `now` is a unix timestamp (injected for tests).
pub fn describe_cert(der: &[u8], now: i64) -> Result<Value, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| "could not parse a certificate".to_string())?;
    let nb = cert.validity().not_before.timestamp();
    let na = cert.validity().not_after.timestamp();
    let mut sans = vec![];
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for n in &ext.value.general_names {
            match n {
                GeneralName::DNSName(d) => sans.push(d.to_string()),
                GeneralName::IPAddress(b) if b.len() == 4 => sans.push(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])),
                GeneralName::IPAddress(b) if b.len() == 16 => sans.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b).unwrap_or([0; 16])).to_string()),
                _ => {}
            }
        }
    }
    let total_sans = sans.len();
    sans.truncate(60);
    let key = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(r)) => format!("RSA {} bit", r.key_size()),
        Ok(PublicKey::EC(_)) => {
            let bits = cert.public_key().subject_public_key.data.len().saturating_sub(1) / 2 * 8;
            format!("EC {bits} bit")
        }
        _ => cert.public_key().algorithm.algorithm.to_id_string(),
    };
    let is_ca = cert.basic_constraints().ok().flatten().is_some_and(|b| b.value.ca);
    Ok(json!({
        "subject": cert.subject().to_string(), "issuer": cert.issuer().to_string(), "serial": cert.raw_serial_as_string(),
        "not_before": fmt_time(nb), "not_after": fmt_time(na), "days_left": (na - now).div_euclid(86_400), "expired": na < now, "not_yet_valid": nb > now,
        "lifetime_days": (na - nb) / 86_400, "sans": sans, "san_count": total_sans, "key": key, "signature": sig_name(&cert.signature_algorithm.algorithm.to_id_string()),
        "is_ca": is_ca, "self_signed": cert.subject() == cert.issuer(), "sha256": Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect::<String>(),
    }))
}

pub fn client_config(verifier: Arc<dyn ServerCertVerifier>) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut cfg = ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("protocol versions").dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Connect to an already vetted address (the SSRF guard resolved it) and read the handshake.
pub fn inspect(addr: SocketAddr, host: &str) -> Result<Value, String> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().map_err(|_| "could not build the certificate verifier".to_string())?;
    let cap = Arc::new(Capture { inner, error: Mutex::new(None) });
    let cfg = client_config(cap.clone());
    let name = ServerName::try_from(host.to_string()).map_err(|_| "host name is not valid for TLS".to_string())?;
    let mut conn = ClientConnection::new(cfg, name).map_err(|_| "could not start TLS".to_string())?;
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(8)).map_err(|_| "could not connect to port 443".to_string())?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = sock.set_write_timeout(Some(Duration::from_secs(8)));
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| format!("TLS handshake failed: {}", e.to_string().chars().take(120).collect::<String>()))?;
    }
    let chain: Vec<Vec<u8>> = conn.peer_certificates().map(|c| c.iter().map(|d| d.as_ref().to_vec()).collect()).unwrap_or_default();
    let version = conn.protocol_version().map(|v| format!("{v:?}").replace("TLSv", "TLS ").replace('_', ".")).unwrap_or_default();
    let cipher = conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())).unwrap_or_default();
    let alpn = conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).to_string());
    let mut stream = StreamOwned::new(conn, sock);
    stream.conn.send_close_notify();
    let _ = stream.conn.complete_io(&mut stream.sock);
    let now = unix_now() as i64;
    let certs: Vec<Value> = chain.iter().filter_map(|d| describe_cert(d, now).ok()).collect();
    let err = cap.error.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(json!({ "version": version, "cipher": cipher, "alpn": alpn, "trusted": err.is_none(), "trust_error": err, "chain": certs,
               "note": "Trust is judged against the Mozilla root set bundled with this plugin; it is not your browser's decision." }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ServerConfig, ServerConnection, pki_types::PrivateKeyDer};
    use std::io::{Read, Write};

    const CERT: &[u8] = include_bytes!("testdata/cert.der");
    const KEY: &[u8] = include_bytes!("testdata/key.der");

    #[test]
    fn describes_a_certificate() {
        let now = unix_now() as i64;
        let c = describe_cert(CERT, now).unwrap();
        assert!(c["subject"].as_str().unwrap().contains("CN=localhost"));
        assert_eq!(c["self_signed"], true);
        assert_eq!(c["sans"], json!(["localhost", "*.test.example", "127.0.0.1"]));
        assert!(c["key"].as_str().unwrap().starts_with("EC 256"), "{}", c["key"]);
        assert!(c["days_left"].as_i64().unwrap() > 3000);
        assert_eq!(c["expired"], false);
        let later = describe_cert(CERT, now + 11 * 365 * 86_400).unwrap();
        assert_eq!(later["expired"], true);
        assert!(describe_cert(b"not a cert", now).is_err());
        assert_eq!(c["sha256"].as_str().unwrap().len(), 64);
        assert!(c["signature"].as_str().unwrap().contains("ecdsa"));
    }

    #[test]
    fn inspects_a_live_handshake_and_flags_untrusted() {
        let provider = Arc::new(rustls_rustcrypto::provider());
        let key = PrivateKeyDer::try_from(KEY.to_vec()).unwrap();
        let cfg = {
            let mut c = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![CertificateDer::from(CERT.to_vec())], key).unwrap();
            c.alpn_protocols = vec![b"h2".to_vec()];
            Arc::new(c)
        };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut conn = ServerConnection::new(cfg).unwrap();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut s).is_err() {
                        return;
                    }
                }
                let mut buf = [0u8; 16];
                let _ = StreamOwned::new(conn, s).read(&mut buf);
            }
        });
        let v = inspect(addr, "localhost").unwrap();
        assert_eq!(v["trusted"], false, "a self-signed certificate is not trusted");
        assert!(v["trust_error"].as_str().is_some());
        assert_eq!(v["alpn"], "h2");
        assert!(v["version"].as_str().unwrap().starts_with("TLS 1."), "{}", v["version"]);
        assert_eq!(v["chain"].as_array().unwrap().len(), 1);
        let _ = std::io::stdout().flush();
    }

    #[test]
    fn handshake_failure_is_an_error_not_a_panic() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nnot tls");
            }
        });
        assert!(inspect(addr, "localhost").is_err());
        assert!(inspect("127.0.0.1:1".parse().unwrap(), "localhost").is_err());
    }
}
