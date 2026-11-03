//! AISStream.io WebSocket client. One background thread, started only while somebody is looking at an area the
//! Finnish feed does not cover, and stopped when nobody has asked for it for a few minutes.
//!
//! Pure Rust: tungstenite does the WebSocket handshake over a blocking socket; for wss:// the socket is wrapped
//! with rustls using the RustCrypto provider (the same one the SDK's HTTPS client uses). The API key is held only
//! inside the thread and is never logged, stored, or returned.

use std::{
    io::ErrorKind,
    net::{TcpStream, ToSocketAddrs},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tungstenite::{Message, WebSocket, client::IntoClientRequest};

use crate::ais::{Decoded, Store, decode_aisstream};

/// The stream is stopped when no request has wanted it for this long.
pub const IDLE_STOP: Duration = Duration::from_secs(5 * 60);

#[derive(Default, Clone)]
#[allow(dead_code)]
pub struct Status {
    pub connected: bool,
    pub messages: u64,
    pub error: Option<String>,
    pub bbox: Option<[f64; 4]>,
}

struct Handle {
    stop: Arc<AtomicBool>,
    bbox: [f64; 4],
    wanted: Arc<Mutex<Instant>>,
    status: Arc<Mutex<Status>>,
    /// set when the service rejected us (bad key etc.); no reconnect attempts until RETRY_AFTER_FATAL has passed
    fatal: Arc<AtomicBool>,
    started: Instant,
}

/// After a rejection (for example a bad API key) the stream is not retried for this long.
pub const RETRY_AFTER_FATAL: Duration = Duration::from_secs(5 * 60);
/// Sessions in a row that end without a single message before the stream gives up (then retried after RETRY_AFTER_FATAL).
pub const EMPTY_SESSIONS_FATAL: u32 = 3;

pub struct Stream {
    url: String,
    inner: Mutex<Option<Handle>>,
}

impl Stream {
    pub fn new(url: String) -> Self {
        Stream { url, inner: Mutex::new(None) }
    }

    /// Make sure a subscription covering `bbox` ([south, west, north, east]) is running. A box that is still
    /// inside the running subscription only refreshes the "wanted" clock; a different area restarts the connection.
    pub fn ensure(&self, store: Arc<Mutex<Store>>, key: String, bbox: [f64; 4]) {
        let mut g = self.inner.lock().unwrap();
        if let Some(h) = g.as_ref() {
            if h.fatal.load(Ordering::SeqCst) && h.started.elapsed() < RETRY_AFTER_FATAL {
                return;
            }
            let running = !h.stop.load(Ordering::SeqCst);
            let covered = h.bbox[0] <= bbox[0] && h.bbox[1] <= bbox[1] && h.bbox[2] >= bbox[2] && h.bbox[3] >= bbox[3];
            if running && covered {
                *h.wanted.lock().unwrap() = Instant::now();
                return;
            }
            h.stop.store(true, Ordering::SeqCst);
        }
        let h = Handle { stop: Arc::new(AtomicBool::new(false)), bbox, wanted: Arc::new(Mutex::new(Instant::now())), status: Arc::new(Mutex::new(Status { bbox: Some(bbox), ..Default::default() })), fatal: Arc::new(AtomicBool::new(false)), started: Instant::now() };
        let (url, stop, wanted, status, fatal) = (self.url.clone(), h.stop.clone(), h.wanted.clone(), h.status.clone(), h.fatal.clone());
        thread::Builder::new().name("aisstream".into()).spawn(move || run(url, key, bbox, store, stop, wanted, status, fatal)).ok();
        *g = Some(h);
    }

    pub fn stop(&self) {
        if let Some(h) = self.inner.lock().unwrap().take() {
            h.stop.store(true, Ordering::SeqCst);
        }
    }

    /// Stop the stream if nobody has wanted it for IDLE_STOP.
    pub fn stop_if_idle(&self) -> bool {
        let idle = self.inner.lock().unwrap().as_ref().is_some_and(|h| h.wanted.lock().unwrap().elapsed() >= IDLE_STOP);
        if idle {
            self.stop();
        }
        idle
    }

    pub fn status(&self) -> Option<Status> {
        self.inner.lock().unwrap().as_ref().filter(|h| !h.stop.load(Ordering::SeqCst) || h.fatal.load(Ordering::SeqCst)).map(|h| h.status.lock().unwrap().clone())
    }
}

pub fn subscription(key: &str, bbox: [f64; 4]) -> String {
    json!({
        "APIKey": key,
        "BoundingBoxes": [[[bbox[0], bbox[1]], [bbox[2], bbox[3]]]],
        "FilterMessageTypes": ["PositionReport", "StandardClassBPositionReport", "ShipStaticData"],
    })
    .to_string()
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|e| e.to_string())?.with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn connect(url: &str) -> Result<WebSocket<Conn>, String> {
    let req = url.into_client_request().map_err(|e| e.to_string())?;
    let uri = req.uri().clone();
    let tls = uri.scheme_str() == Some("wss");
    let host = uri.host().ok_or("no host in stream URL")?.to_string();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let addr = (host.as_str(), port).to_socket_addrs().map_err(|e| format!("resolve {host}: {e}"))?.next().ok_or("no address")?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| format!("connect: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();
    tcp.set_nodelay(true).ok();
    let stream = if tls {
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(tls_config()?, name).map_err(|e| e.to_string())?;
        Conn::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        Conn::Plain(tcp)
    };
    let (ws, _) = tungstenite::client::client(req, stream).map_err(|e| format!("websocket handshake: {e}"))?;
    Ok(ws)
}

/// A socket that is either plain (local tests) or wrapped in rustls (the real wss:// feed).
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}
impl std::io::Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}
impl std::io::Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

fn run(url: String, key: String, bbox: [f64; 4], store: Arc<Mutex<Store>>, stop: Arc<AtomicBool>, wanted: Arc<Mutex<Instant>>, status: Arc<Mutex<Status>>, fatal: Arc<AtomicBool>) {
    let mut backoff: u64 = if cfg!(test) { 0 } else { 3 };
    let mut empty_sessions = 0u32;
    while !stop.load(Ordering::SeqCst) {
        match connect(&url) {
            Ok(mut ws) => {
                if let Err(e) = ws.send(Message::text(subscription(&key, bbox))) {
                    set_error(&status, format!("subscribe failed: {e}"));
                } else {
                    {
                        let mut s = status.lock().unwrap();
                        s.connected = true;
                        s.error = None;
                    }
                    let before = status.lock().unwrap().messages;
                    let rejected = pump(&mut ws, &store, &stop, &wanted, &status);
                    status.lock().unwrap().connected = false;
                    let _ = ws.close(None);
                    if rejected {
                        // Bad key or similar: retrying only hammers the service.
                        fatal.store(true, Ordering::SeqCst);
                        stop.store(true, Ordering::SeqCst);
                        return;
                    }
                    // A session that delivered nothing is treated like a failure (a rejected key often just resets the socket).
                    if status.lock().unwrap().messages > before {
                        backoff = if cfg!(test) { 0 } else { 3 };
                        empty_sessions = 0;
                    } else {
                        empty_sessions += 1;
                        if empty_sessions >= EMPTY_SESSIONS_FATAL {
                            // AISStream resets the socket without a message for a rejected key; stop hammering it.
                            set_error(&status, "AISStream closed the connection without sending data several times in a row; the API key (AISSTREAM_API_KEY) may be invalid or revoked, or the service is down. Check the Credentials page.".into());
                            fatal.store(true, Ordering::SeqCst);
                            stop.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                }
            }
            Err(e) => set_error(&status, e),
        }
        // Back off before reconnecting, in small steps so a stop request is noticed quickly.
        for _ in 0..backoff * 4 {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }
        thread::sleep(Duration::from_millis(20));
        backoff = (backoff * 2).min(60);
    }
}

fn set_error(status: &Arc<Mutex<Status>>, e: String) {
    // Error text never contains the key: it is only ever placed in the subscription frame.
    status.lock().unwrap().error = Some(e);
}

/// Reads until stopped or the connection ends. Returns true when the service reported an error that retrying will not fix.
fn pump(ws: &mut WebSocket<Conn>, store: &Arc<Mutex<Store>>, stop: &AtomicBool, wanted: &Mutex<Instant>, status: &Arc<Mutex<Status>>) -> bool {
    while !stop.load(Ordering::SeqCst) {
        if wanted.lock().unwrap().elapsed() >= IDLE_STOP {
            stop.store(true, Ordering::SeqCst);
            return false;
        }
        match ws.read() {
            Ok(Message::Text(t)) => {
                let Ok(v) = serde_json::from_str::<Value>(t.as_str()) else { continue };
                match decode_aisstream(&v) {
                    Some(Decoded::Position(p, name)) => {
                        let mut s = store.lock().unwrap();
                        if let Some(n) = name {
                            let mmsi = p.mmsi;
                            if s.info.get(&mmsi).is_none_or(|i| i.name.is_none()) {
                                let mut i = s.info.get(&mmsi).cloned().unwrap_or_default();
                                i.name = Some(n);
                                s.set_info(mmsi, i);
                            }
                        }
                        s.update(p);
                        drop(s);
                        status.lock().unwrap().messages += 1;
                    }
                    Some(Decoded::Static(m, i)) => {
                        let mut s = store.lock().unwrap();
                        let mut merged = s.info.get(&m).cloned().unwrap_or_default();
                        merged.name = i.name.or(merged.name);
                        merged.call_sign = i.call_sign.or(merged.call_sign);
                        merged.imo = i.imo.or(merged.imo);
                        merged.ship_type = i.ship_type.or(merged.ship_type);
                        merged.destination = i.destination.or(merged.destination);
                        merged.eta = i.eta.or(merged.eta);
                        merged.draught_m = i.draught_m.or(merged.draught_m);
                        merged.length_m = i.length_m.or(merged.length_m);
                        merged.beam_m = i.beam_m.or(merged.beam_m);
                        s.set_info(m, merged);
                    }
                    Some(Decoded::Error(e)) => {
                        set_error(status, format!("AISStream: {e}"));
                        return true;
                    }
                    None => {}
                }
            }
            Ok(Message::Close(_)) => return false,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => {
                set_error(status, format!("stream ended: {}", if matches!(e, tungstenite::Error::Protocol(_)) { "the server dropped the connection".to_string() } else { e.to_string() }));
                return false;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn subscription_shape() {
        let v: Value = serde_json::from_str(&subscription("K", [59.0, 20.0, 61.0, 26.0])).unwrap();
        assert_eq!(v["APIKey"], "K");
        assert_eq!(v["BoundingBoxes"][0][0], json!([59.0, 20.0]));
        assert_eq!(v["BoundingBoxes"][0][1], json!([61.0, 26.0]));
    }

    /// A local fake AISStream: accepts one client, checks the subscription, sends two frames, then keeps the socket open.
    fn fake_server(frames: Vec<String>) -> (String, std::sync::mpsc::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/v0/stream", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                let mut ws = tungstenite::accept(s).unwrap();
                if let Ok(Message::Text(t)) = ws.read() {
                    tx.send(t.as_str().to_string()).ok();
                }
                for f in frames {
                    ws.send(Message::text(f)).ok();
                }
                thread::sleep(Duration::from_secs(3));
            }
        });
        (url, rx)
    }

    fn wait_for(f: impl Fn() -> bool) -> bool {
        for _ in 0..80 {
            if f() {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn receives_positions_and_static_data() {
        let pos = json!({"MessageType":"PositionReport","MetaData":{"MMSI":259000420,"ShipName":"AUGUSTSON ","latitude":60.1,"longitude":24.9,"time_utc":"2099-01-01 00:00:00.0 +0000 UTC"},"Message":{"PositionReport":{"Cog":10,"Latitude":60.1,"Longitude":24.9,"NavigationalStatus":0,"Sog":5.0,"TrueHeading":12,"UserID":259000420}}});
        let st = json!({"MessageType":"ShipStaticData","MetaData":{"MMSI":259000420},"Message":{"ShipStaticData":{"Name":"AUGUSTSON","Destination":"BERGEN","ImoNumber":9074729,"Type":70,"UserID":259000420,"Dimension":{"A":10,"B":10,"C":3,"D":3}}}});
        let (url, rx) = fake_server(vec![pos.to_string(), "not json".into(), st.to_string()]);
        let store = Arc::new(Mutex::new(Store::default()));
        let s = Stream::new(url);
        s.ensure(store.clone(), "SECRET-KEY".into(), [59.0, 24.0, 61.0, 26.0]);
        let sub = rx.recv_timeout(Duration::from_secs(5)).expect("subscription frame");
        assert!(sub.contains("SECRET-KEY") && sub.contains("BoundingBoxes"));
        assert!(wait_for(|| store.lock().unwrap().pos.contains_key(&259_000_420) && store.lock().unwrap().info.get(&259_000_420).is_some_and(|i| i.imo.is_some())), "frames decoded into the store");
        let g = store.lock().unwrap();
        assert_eq!(g.info[&259_000_420].destination.as_deref(), Some("BERGEN"));
        drop(g);
        let status = s.status().expect("running");
        assert!(status.connected && status.messages >= 1);
        assert!(!format!("{:?}", status.error).contains("SECRET-KEY"));
        // Same area again does not restart; stopping hides the status.
        s.ensure(store, "SECRET-KEY".into(), [59.5, 24.5, 60.5, 25.5]);
        assert!(s.status().is_some());
        s.stop();
        assert!(s.status().is_none());
    }

    #[test]
    fn service_error_stops_retrying_and_is_reported() {
        let (url, _rx) = fake_server(vec![json!({"error":"Api Key Is Not Valid"}).to_string()]);
        let store = Arc::new(Mutex::new(Store::default()));
        let s = Stream::new(url);
        s.ensure(store, "bad".into(), [0.0, 0.0, 1.0, 1.0]);
        let inner_status = {
            assert!(wait_for(|| s.inner.lock().unwrap().as_ref().is_some_and(|h| h.stop.load(Ordering::SeqCst))), "thread stops itself after a fatal error");
            let g = s.inner.lock().unwrap();
            g.as_ref().unwrap().status.lock().unwrap().clone()
        };
        assert!(inner_status.error.unwrap().contains("Api Key Is Not Valid"));
        let st = s.status().expect("a rejected stream keeps reporting why");
        assert!(!st.connected && st.error.is_some());
        // and is not restarted by the next request
        s.ensure(Arc::new(Mutex::new(Store::default())), "bad".into(), [0.0, 0.0, 1.0, 1.0]);
        assert!(s.inner.lock().unwrap().as_ref().unwrap().fatal.load(Ordering::SeqCst));
    }

    #[test]
    fn repeated_empty_sessions_are_fatal_with_a_helpful_message() {
        // A server that accepts, reads the subscription and drops the socket (what AISStream does for a bad key).
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/v0/stream", l.local_addr().unwrap());
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                if let Ok(mut ws) = tungstenite::accept(s) {
                    let _ = ws.read();
                }
            }
        });
        let s = Stream::new(url);
        s.ensure(Arc::new(Mutex::new(Store::default())), "SECRET-KEY".into(), [0.0, 0.0, 1.0, 1.0]);
        assert!(wait_for(|| s.inner.lock().unwrap().as_ref().is_some_and(|h| h.fatal.load(Ordering::SeqCst))), "gives up after repeated empty sessions");
        let st = s.status().expect("keeps reporting why");
        let err = st.error.unwrap();
        assert!(err.contains("AISSTREAM_API_KEY") && !err.contains("SECRET-KEY"), "{err}");
    }

    #[test]
    fn connect_failure_is_reported_not_fatal() {
        let store = Arc::new(Mutex::new(Store::default()));
        let s = Stream::new("ws://127.0.0.1:1/x".into());
        s.ensure(store, "k".into(), [0.0, 0.0, 1.0, 1.0]);
        assert!(wait_for(|| s.status().is_some_and(|st| st.error.is_some())));
        s.stop();
    }

    #[test]
    fn idle_stop() {
        let store = Arc::new(Mutex::new(Store::default()));
        let s = Stream::new("ws://127.0.0.1:1/x".into());
        s.ensure(store, "k".into(), [0.0, 0.0, 1.0, 1.0]);
        assert!(!s.stop_if_idle());
        *s.inner.lock().unwrap().as_ref().unwrap().wanted.lock().unwrap() = Instant::now() - IDLE_STOP - Duration::from_secs(1);
        assert!(s.stop_if_idle());
        assert!(s.status().is_none());
    }
}
