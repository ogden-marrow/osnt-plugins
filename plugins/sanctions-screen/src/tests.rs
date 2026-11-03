use super::*;
use axum::{extract::State as AState, routing::get as aget};
use std::sync::atomic::{AtomicUsize, Ordering};

const HDR: &str = "\"id\",\"schema\",\"name\",\"aliases\",\"birth_date\",\"countries\",\"addresses\",\"identifiers\",\"sanctions\",\"phones\",\"emails\",\"program_ids\",\"dataset\",\"first_seen\",\"last_seen\",\"last_change\"\n";

fn csv_fixture() -> String {
    let rows = [
        "\"NK-org1\",\"Organization\",\"Rosneft Oil Company\",\"PJSC Rosneft;Rosneft Oil Co\",\"\",\"ru\",\"Sofiyskaya 26 Moscow\",\"1027700043502\",\"UKR - Executive Order 14024\",\"+7 111\",\"a@b.ru\",\"US-UKR\",\"OFAC\",\"2014-09-12T10:00:00\",\"2026-11-03T04:00:00\",\"2026-01-01T00:00:00\"",
        "\"NK-per1\",\"Person\",\"Ivan Petrovich Sidorov\",\"Vanya Sidorov\",\"1970-02-03\",\"ru\",\"12 Private Street\",\"passport 123\",\"RUSSIA-EO14024\",\"+7 222\",\"ivan@x.ru\",\"US-RUSHAR\",\"OFAC\",\"2022-03-24T10:00:00\",\"2026-11-03T04:00:00\",\"2026-01-01T00:00:00\"",
        "\"NK-ves1\",\"Vessel\",\"NURKEZ\",\"\",\"\",\"pa\",\"\",\"352002470;3E2311;IMO9253325\",\"RUSSIA-EO14024\",\"\",\"\",\"US-RUSHAR\",\"OFAC\",\"2025-01-10T16:10:02\",\"2026-11-03T04:00:00\",\"2026-01-06T00:00:00\"",
        "\"NK-air1\",\"Airplane\",\"EX-301\",\"\",\"\",\"\",\"\",\"524\",\"SDGT\",\"\",\"\",\"US-TERR\",\"OFAC\",\"2023-04-20T10:27:20\",\"2026-11-03T04:00:00\",\"2026-01-06T00:00:00\"",
        "\"NK-w1\",\"CryptoWallet\",\"bc1qrosneftwallet\",\"\",\"\",\"\",\"\",\"\",\"SDN\",\"\",\"\",\"\",\"OFAC\",\"2023-04-20T10:27:20\",\"2026-11-03T04:00:00\",\"2026-01-06T00:00:00\"",
        "\"NK-le1\",\"LegalEntity\",\"MICHAEL DAVID MUMMERT\",\"\",\"\",\"\",\"INMATE NUMBER: 38011-509\",\"\",\"89 F.R. 20942\",\"\",\"\",\"US-BIS-DPL\",\"BIS\",\"2025-10-31T11:32:56\",\"2026-11-03T04:00:00\",\"2025-10-31T11:32:56\"",
    ];
    format!("{HDR}{}\n", rows.join("\n"))
}

#[test]
fn parse_drops_unsupported_and_strips_person_fields() {
    let d = parse_csv(csv_fixture().as_bytes(), 1).unwrap();
    assert_eq!(d.recs.len(), 5, "crypto wallet rows are not loaded");
    let per = d.recs.iter().find(|r| r.id == "NK-per1").unwrap();
    assert!(per.aliases.is_empty() && per.countries.is_empty() && per.idents.is_empty());
    let org = d.recs.iter().find(|r| r.id == "NK-org1").unwrap();
    assert_eq!(org.aliases.len(), 2);
    assert_eq!(org.first_seen, "2014-09-12");
    assert!(parse_csv(b"a,b\n1,2\n", 1).is_err());
}

#[test]
fn identifier_validation() {
    assert_eq!(imo_valid("IMO 9253325").as_deref(), Some("IMO9253325"));
    assert_eq!(imo_valid("9253325").as_deref(), Some("IMO9253325"));
    assert!(imo_valid("9253326").is_none(), "bad check digit");
    assert!(imo_valid("12345").is_none());
    assert_eq!(mmsi_valid("352002470").as_deref(), Some("352002470"));
    assert!(mmsi_valid("35200247").is_none() && mmsi_valid("0123456789").is_none() && mmsi_valid("35200247x").is_none());
    assert_eq!(reg_valid("ex-301").as_deref(), Some("EX301"));
    assert!(reg_valid("a").is_none() && reg_valid("../x").is_none());
}

struct Fake {
    hits: AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}

async fn start(dir: Option<PathBuf>, fake: Arc<Fake>, open: bool) -> String {
    let up = Router::new()
        .route("/{id}/targets.simple.csv", aget(|AState(f): AState<Arc<Fake>>| async move {
            f.hits.fetch_add(1, Ordering::SeqCst);
            if f.fail.load(Ordering::SeqCst) { (StatusCode::INTERNAL_SERVER_ERROR, String::new()) } else { (StatusCode::OK, csv_fixture()) }
        }))
        .with_state(fake);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, up).await.unwrap() });
    let st = new_state(Config { base, open, ttl: Duration::from_secs(3600), dir });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    url
}

fn fake() -> Arc<Fake> {
    Arc::new(Fake { hits: AtomicUsize::new(0), fail: false.into() })
}

async fn call(method: &'static str, url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = if method == "POST" { agent.post(&url).send_empty().unwrap() } else { agent.get(&url).call().unwrap() };
        (r.status().as_u16(), r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn entity_search_hides_persons_by_default() {
    let url = start(None, fake(), true).await;
    let (c, v) = call("GET", format!("{url}/api/search?q=rosneft%20oil%20company&lists=us_ofac_sdn")).await;
    assert_eq!(c, 200);
    assert_eq!(v["results"][0]["id"], "NK-org1");
    assert_eq!(v["results"][0]["matched_on"], "name");
    assert!(v["results"][0]["explanation"].is_array());
    assert_eq!(v["results"][0]["aliases"].as_array().unwrap().len(), 2);
    let txt = v.to_string();
    assert!(!txt.contains("Sofiyskaya") && !txt.contains("+7 111") && !txt.contains("a@b.ru"), "no addresses, phones or emails");
    let (_, v) = call("GET", format!("{url}/api/search?q=ivan%20sidorov&lists=us_ofac_sdn&min=0.6")).await;
    assert_eq!(v["total_matches"], 0, "persons are off by default");
    let (_, v) = call("GET", format!("{url}/api/search?q=ivan%20sidorov&lists=us_ofac_sdn&persons=1")).await;
    let r = &v["results"][0];
    assert_eq!(r["id"], "NK-per1");
    assert_eq!(r["minimal"], true);
    let txt = r.to_string();
    for banned in ["1970", "Private Street", "passport", "ivan@x.ru", "+7 222", "Vanya", "\"ru\""] {
        assert!(!txt.contains(banned), "person result leaks {banned}: {txt}");
    }
    assert_eq!(r["programme"], "", "free-text listing reasons about persons are not returned");
    assert!(r.get("aliases").is_none() && r.get("countries").is_none() && r.get("identifiers").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn unclassified_records_are_treated_like_persons() {
    let url = start(None, fake(), true).await;
    let (_, v) = call("GET", format!("{url}/api/search?q=michael%20mummert&lists=us_bis_denied")).await;
    assert_eq!(v["total_matches"], 0);
    let (_, v) = call("GET", format!("{url}/api/search?q=michael%20mummert&lists=us_bis_denied&persons=1")).await;
    assert_eq!(v["results"][0]["kind"], "unclassified");
    assert!(!v.to_string().contains("INMATE"));
}

#[tokio::test(flavor = "multi_thread")]
async fn alias_fuzzy_and_validation() {
    let url = start(None, fake(), true).await;
    let (_, v) = call("GET", format!("{url}/api/search?q=pjsc%20rosnef&lists=us_ofac_sdn")).await;
    assert_eq!(v["results"][0]["id"], "NK-org1");
    for q in ["q=", "q=a", "q=!!!", "q=rosneft&lists=nope", "q=rosneft&kinds=person"] {
        let (c, _) = call("GET", format!("{url}/api/search?{q}")).await;
        assert_eq!(c, 400, "{q}");
    }
    let (_, v) = call("GET", format!("{url}/api/search?q=rosneft&lists=us_ofac_sdn&min=0.99")).await;
    assert!(v["min_score"].as_f64().unwrap() <= 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn identifier_crosscheck() {
    let url = start(None, fake(), true).await;
    let (c, v) = call("GET", format!("{url}/api/identifier?imo=9253325")).await;
    assert_eq!(c, 200);
    assert_eq!(v["listed"], true);
    assert_eq!(v["matches"][0]["name"], "NURKEZ");
    let (_, v) = call("GET", format!("{url}/api/identifier?mmsi=352002470")).await;
    assert_eq!(v["listed"], true);
    let (_, v) = call("GET", format!("{url}/api/identifier?reg=EX301")).await;
    assert_eq!(v["matches"][0]["kind"], "aircraft");
    let (_, v) = call("GET", format!("{url}/api/identifier?mmsi=111111111")).await;
    assert_eq!(v["listed"], false);
    for q in ["imo=9253326", "", "imo=9253325&mmsi=352002470", "reg=%2F"] {
        assert_eq!(call("GET", format!("{url}/api/identifier?{q}")).await.0, 400, "{q}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn caches_on_disk_and_survives_restart_and_outage() {
    let dir = std::env::temp_dir().join(format!("osnt-sanc-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let f = fake();
    let url = start(Some(dir.clone()), f.clone(), true).await;
    call("GET", format!("{url}/api/search?q=rosneft&lists=us_ofac_sdn")).await;
    call("GET", format!("{url}/api/search?q=nurkez&lists=us_ofac_sdn")).await;
    assert_eq!(f.hits.load(Ordering::SeqCst), 1, "one download serves both searches");
    assert!(dir.join("us_ofac_sdn.csv").exists());
    // Restart with the upstream down: the cached file is fresh, so nothing is downloaded.
    let f2 = fake();
    f2.fail.store(true, Ordering::SeqCst);
    let url2 = start(Some(dir.clone()), f2.clone(), true).await;
    let (c, v) = call("GET", format!("{url2}/api/search?q=rosneft&lists=us_ofac_sdn")).await;
    assert_eq!((c, f2.hits.load(Ordering::SeqCst)), (200, 0));
    assert_eq!(v["lists"][0]["stale"], false);
    // Forced refresh while the upstream is down falls back to the stale copy and says so.
    let (c, v) = call("POST", format!("{url2}/api/lists/refresh?list=us_ofac_sdn")).await;
    assert_eq!((c, v["stale"].clone()), (200, json!(true)));
    let (c, _) = call("POST", format!("{url2}/api/lists/refresh?list=us_ofac_sdn")).await;
    assert_eq!(c, 429, "refresh is rate limited");
    // A list never downloaded and an upstream error is reported as a gateway error.
    let (c, v) = call("GET", format!("{url2}/api/search?q=rosneft&lists=eu_fsf")).await;
    assert_eq!(c, 502);
    assert!(!v["error"].as_str().unwrap().contains("127.0.0.1"));
    let (_, v) = call("GET", format!("{url2}/api/lists")).await;
    assert_eq!(v["lists"][0]["loaded"], true);
    assert_eq!(v["lists"][0]["entities"], 1);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn cleanup_removes_old_files_and_enforces_cap() {
    let dir = std::env::temp_dir().join(format!("osnt-sanc-clean-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for i in 0..4 {
        fs::write(dir.join(format!("l{i}.csv")), vec![b'x'; 1000]).unwrap();
        std::thread::sleep(Duration::from_millis(15));
    }
    fs::write(dir.join("junk.tmp"), b"x").unwrap();
    cleanup_dir(&dir, Duration::from_secs(3600), 2500);
    let left: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left.contains(&"l3.csv".to_string()) && !left.iter().any(|n| n.ends_with(".tmp")));
    cleanup_dir(&dir, Duration::from_millis(0), 1 << 30);
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_and_tools() {
    let url = start(None, fake(), false).await;
    assert_eq!(call("GET", format!("{url}/api/lists")).await.0, 401);
    assert_eq!(call("POST", format!("{url}/api/lists/refresh?list=eu_fsf")).await.0, 401);
    let (c, v) = call("GET", format!("{url}/tools")).await;
    assert_eq!(c, 200);
    assert_eq!(v.as_array().unwrap().len(), 3);
}
