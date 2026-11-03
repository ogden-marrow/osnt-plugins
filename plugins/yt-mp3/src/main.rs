use std::{env, net::SocketAddr};

#[tokio::main]
async fn main() {
    let cfg = yt_mp3::Config::from_env();
    let app = yt_mp3::build(cfg).await;
    let addr: SocketAddr = env::var("OSNT_YTMP3_BIND").unwrap_or_else(|_| "127.0.0.1:8122".into()).parse().expect("bind addr");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("yt-mp3 plugin on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}
