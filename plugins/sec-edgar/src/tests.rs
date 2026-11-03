use super::*;
use axum::{extract::State as AState, http::HeaderMap, routing::get as aget};
use std::sync::atomic::{AtomicUsize, Ordering};

fn sub_fixture() -> Value {
    json!({
        "cik": "0000320193", "entityType": "operating", "sic": "3571", "sicDescription": "Electronic Computers", "name": "Apple Inc.",
        "tickers": ["AAPL"], "exchanges": ["Nasdaq"], "category": "Large accelerated filer", "fiscalYearEnd": "0926",
        "stateOfIncorporation": "CA", "stateOfIncorporationDescription": "CA", "phone": "(408) 996-1010", "website": "",
        "ein": "942404110",
        "addresses": { "business": { "street1": "ONE APPLE PARK WAY", "street2": null, "city": "CUPERTINO", "stateOrCountry": "CA", "stateOrCountryDescription": "CA", "zipCode": "95014" }, "mailing": null },
        "formerNames": [{ "name": "APPLE COMPUTER INC", "from": "1994-01-26T00:00:00.000Z", "to": "2007-01-04T00:00:00.000Z" }],
        "filings": {
            "recent": {
                "accessionNumber": ["0000320193-26-000024", "0001140361-26-041201", "0000320193-25-000079", "0000320193-25-000071"],
                "filingDate": ["2026-11-02", "2026-10-29", "2025-10-31", "2025-08-01"],
                "reportDate": ["2026-11-01", "", "2025-09-27", "2025-06-28"],
                "form": ["8-K", "4", "10-K", "10-Q"],
                "items": ["2.02,9.01", "", "", ""],
                "primaryDocument": ["aapl-20261102.htm", "xslF345X06/form4.xml", "aapl-20250927.htm", "aapl-20250628.htm"],
                "primaryDocDescription": ["8-K", "FORM 4", "10-K", "10-Q"]
            },
            "files": [{ "name": "CIK0000320193-submissions-001.json", "filingCount": 1271 }]
        }
    })
}

#[test]
fn cik_parsing() {
    assert_eq!(parse_cik("320193").as_deref(), Some("0000320193"));
    assert_eq!(parse_cik(" CIK0000320193 ").as_deref(), Some("0000320193"));
    assert_eq!(parse_cik("cik12").as_deref(), Some("0000000012"));
    assert_eq!(parse_cik("0"), None);
    assert_eq!(parse_cik("12345678901"), None);
    assert_eq!(parse_cik("12a4"), None);
    assert_eq!(parse_cik("../etc"), None);
    assert_eq!(parse_cik(""), None);
}

#[test]
fn contact_validation() {
    assert!(validate_contact("me@example.org").is_some());
    assert!(validate_contact("  https://example.org/contact ").is_some());
    assert!(validate_contact("no contact here").is_none());
    assert!(validate_contact("a@b").is_none(), "too short");
    assert!(validate_contact("x@example.org\r\nX-Evil: 1").is_none(), "control characters");
    assert!(validate_contact("jürgen@example.org").is_none(), "non-ascii is not a safe header value");
    assert!(validate_contact(&format!("{}@example.org", "a".repeat(200))).is_none());
}

#[test]
fn ticker_ranking() {
    let rows: Vec<Value> = vec![
        json!([320193, "Apple Inc.", "AAPL", "Nasdaq"]),
        json!([1, "Apple Hospitality REIT, Inc.", "APLE", "NYSE"]),
        json!([789019, "MICROSOFT CORP", "MSFT", "Nasdaq"]),
        json!([1652044, "Alphabet Inc.", "GOOGL", "Nasdaq"]),
        json!([1652044, "Alphabet Inc.", "GOOG", "Nasdaq"]),
    ];
    let m = rank_tickers(&rows, "aapl", 10);
    assert_eq!(m[0].cik, 320193);
    assert_eq!(m[0].score, 100);
    let m = rank_tickers(&rows, "apple", 10);
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].name, "Apple Inc.", "shorter name ranks first at equal score");
    let m = rank_tickers(&rows, "alphabet", 10);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].tickers.len(), 2, "tickers of one CIK are merged");
    assert!(rank_tickers(&rows, "hospitality reit", 10).iter().any(|x| x.cik == 1));
    assert!(rank_tickers(&rows, "zzz", 10).is_empty());
    assert!(rank_tickers(&rows, "  ", 10).is_empty());
    assert_eq!(rank_tickers(&rows, "a", 1).len(), 1, "limit applies");
}

#[test]
fn profile_is_company_level_only() {
    let p = build_profile(&sub_fixture());
    assert_eq!(p["cik"], "0000320193");
    assert_eq!(p["name"], "Apple Inc.");
    assert_eq!(p["fiscal_year_end"], "Sep 26");
    assert_eq!(p["business_address"], "ONE APPLE PARK WAY, CUPERTINO, CA, 95014");
    assert_eq!(p["mailing_address"], Value::Null);
    assert_eq!(p["former_names"][0]["from"], "1994-01-26");
    assert_eq!(p["older_filings_not_listed"], 1271);
    assert!(p["website"].is_null());
    let txt = p.to_string();
    assert!(!txt.contains("942404110"), "EIN is not returned");
}

#[test]
fn individuals_are_not_companies() {
    assert!(is_company(&sub_fixture()));
    assert!(!is_company(&json!({ "entityType": "other", "sic": "", "tickers": [], "name": "COOK TIMOTHY D" })));
    assert!(is_company(&json!({ "entityType": "other", "sic": "6770", "tickers": [] })), "a blank-check shell has a SIC code");
    assert!(is_company(&json!({ "entityType": "", "sic": "", "tickers": ["XYZ"] })));
}

#[test]
fn filings_filter_limit_and_links() {
    let (rows, total) = build_filings(&sub_fixture(), &[], 10);
    assert_eq!((rows.len(), total), (4, 4));
    assert_eq!(rows[0]["items"][0]["label"], "Results of operations");
    assert_eq!(rows[2]["document_url"], "https://www.sec.gov/Archives/edgar/data/320193/000032019325000079/aapl-20250927.htm");
    assert_eq!(rows[2]["index_url"], "https://www.sec.gov/Archives/edgar/data/320193/000032019325000079/0000320193-25-000079-index.htm");
    let (rows, total) = build_filings(&sub_fixture(), &["10-K".into(), "10-Q".into()], 1);
    assert_eq!((rows.len(), total), (1, 2));
    assert_eq!(rows[0]["form"], "10-K");
    let (rows, _) = build_filings(&sub_fixture(), &["10-K".into()], 5);
    assert_eq!(rows.len(), 1);
    assert!(form_matches("10-K/A", &["10-K".into()]), "amendments match their base form");
    assert!(!form_matches("10-KT", &["10-K".into()]));
    assert!(form_group("annual").unwrap().contains(&"20-F"));
    assert!(form_group("bogus").is_none());
}

#[test]
fn dates() {
    assert_eq!(iso_days("1970-01-01"), Some(0));
    assert_eq!(iso_days("2000-03-01"), Some(11017));
    assert_eq!(iso_days("2026-13-01"), None);
    assert_eq!(iso_days("nope"), None);
    assert_eq!(iso_days("2024-12-31T00:00:00Z").unwrap() - iso_days("2024-01-01").unwrap(), 365);
}

#[test]
fn annual_facts_only_with_dedupe() {
    let v = json!({ "units": { "USD": [
        { "start": "2023-10-01", "end": "2024-09-28", "val": 100.0, "fy": 2024, "fp": "FY", "form": "10-K", "filed": "2024-11-01", "accn": "a" },
        { "start": "2023-10-01", "end": "2024-09-28", "val": 101.0, "fy": 2024, "fp": "FY", "form": "10-K/A", "filed": "2024-12-01", "accn": "b" },
        { "start": "2024-04-01", "end": "2024-06-29", "val": 25.0, "fy": 2024, "fp": "Q3", "form": "10-Q", "filed": "2024-08-01", "accn": "c" },
        { "start": "2024-04-01", "end": "2024-06-29", "val": 26.0, "fy": 2024, "fp": "FY", "form": "10-K", "filed": "2024-11-01", "accn": "d" },
        { "start": "2024-09-29", "end": "2025-09-27", "val": 120.0, "fy": 2025, "fp": "FY", "form": "10-K", "filed": "2025-10-31", "accn": "e" }
    ] } });
    let (s, unit) = facts_series(&v, true);
    assert_eq!(unit.as_deref(), Some("USD"));
    assert_eq!(s.len(), 2, "quarter-length durations are dropped");
    assert_eq!(s[0]["value"], 101.0, "latest filing wins for the same period end");
    assert_eq!(s[1]["end"], "2025-09-27");
    let inst = json!({ "units": { "USD": [{ "end": "2025-09-27", "val": 5.0, "fy": 2025, "fp": "FY", "form": "10-K", "filed": "2025-10-31", "accn": "e" }] } });
    assert_eq!(facts_series(&inst, false).0.len(), 1);
    assert!(facts_series(&json!({}), true).0.is_empty());
}

#[test]
fn exhibit21_detection() {
    let idx = json!({ "directory": { "item": [{ "name": "aapl-20250927.htm" }, { "name": "a10-kexhibit23109272025.htm" }, { "name": "a10-kexhibit21109272025.htm" }, { "name": "R1.htm" }] } });
    assert_eq!(find_exhibit21(&idx).as_deref(), Some("a10-kexhibit21109272025.htm"));
    let idx = json!({ "directory": { "item": [{ "name": "ex-21.htm" }] } });
    assert_eq!(find_exhibit21(&idx).as_deref(), Some("ex-21.htm"));
    assert!(find_exhibit21(&json!({ "directory": { "item": [{ "name": "ex210.htm" }, { "name": "ex21.pdf" }] } })).is_none());
    assert!(find_exhibit21(&json!({})).is_none());
}

// ---- integration against a fake SEC ----------------------------------------------------------------------------

struct Fake {
    hits: AtomicUsize,
}

async fn fake_json(AState(f): AState<Arc<Fake>>, headers: HeaderMap, body: Value) -> (StatusCode, String) {
    f.hits.fetch_add(1, Ordering::SeqCst);
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ua.contains("tester@example.org") {
        return (StatusCode::FORBIDDEN, "<html>Undeclared Automated Tool</html>".into());
    }
    (StatusCode::OK, body.to_string())
}

async fn start_fake() -> (String, Arc<Fake>) {
    let f = Arc::new(Fake { hits: AtomicUsize::new(0) });
    let concept = |end: &'static str, val: f64, filed: &'static str| json!({ "cik": 320193, "units": { "USD": [{ "end": end, "val": val, "fy": 2025, "fp": "FY", "form": "10-K", "filed": filed, "accn": "x" }] } });
    let r = Router::new()
        .route("/files/company_tickers_exchange.json", aget(|s: AState<Arc<Fake>>, h: HeaderMap| async move { fake_json(s, h, json!({ "fields": ["cik", "name", "ticker", "exchange"], "data": [[320193, "Apple Inc.", "AAPL", "Nasdaq"], [789019, "MICROSOFT CORP", "MSFT", "Nasdaq"]] })).await }))
        .route("/submissions/CIK0000320193.json", aget(|s: AState<Arc<Fake>>, h: HeaderMap| async move { fake_json(s, h, sub_fixture()).await }))
        .route("/submissions/CIK0001214156.json", aget(|s: AState<Arc<Fake>>, h: HeaderMap| async move { fake_json(s, h, json!({ "cik": "0001214156", "entityType": "other", "sic": "", "name": "COOK TIMOTHY D", "tickers": [], "filings": { "recent": {} } })).await }))
        .route("/api/xbrl/companyconcept/CIK0000320193/us-gaap/Assets.json", aget(move |s: AState<Arc<Fake>>, h: HeaderMap| async move { fake_json(s, h, concept("2025-09-27", 359241000000.0, "2025-10-31")).await }))
        .route("/Archives/edgar/data/320193/000032019325000079/index.json", aget(|s: AState<Arc<Fake>>, h: HeaderMap| async move { fake_json(s, h, json!({ "directory": { "item": [{ "name": "ex21.htm" }, { "name": "aapl.htm" }] } })).await }))
        .with_state(f.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    (base, f)
}

async fn start_app(contact: Option<&'static str>, open: bool) -> (String, Arc<Fake>) {
    let (base, fake) = start_fake().await;
    let st = new_state(Config { data_base: base.clone(), www_base: base, gap: Duration::from_millis(1), open }, None, Box::new(move || contact.map(str::to_string)));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    (url, fake)
}

async fn call(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        let code = r.status().as_u16();
        (code, r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_without_contact_and_never_calls_sec() {
    let (url, fake) = start_app(None, true).await;
    let (code, v) = call(format!("{url}/api/company?cik=320193")).await;
    assert_eq!(code, 503);
    assert!(v["error"].as_str().unwrap().contains("SEC_CONTACT"));
    assert_eq!(fake.hits.load(Ordering::SeqCst), 0);
    let (code, _) = call(format!("{url}/api/search?q=apple")).await;
    assert_eq!(code, 503);
    assert_eq!(fake.hits.load(Ordering::SeqCst), 0);
    let (code, v) = call(format!("{url}/api/status")).await;
    assert_eq!((code, v["contact_set"].clone()), (200, json!(false)));
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_with_contact_and_cache() {
    let (url, fake) = start_app(Some("tester@example.org"), true).await;
    let (code, v) = call(format!("{url}/api/search?q=AAPL")).await;
    assert_eq!(code, 200);
    assert_eq!(v["matches"][0]["cik"], "0000320193");
    let (_, v) = call(format!("{url}/api/company?cik=320193")).await;
    assert_eq!(v["company"]["name"], "Apple Inc.");
    let before = fake.hits.load(Ordering::SeqCst);
    let (_, v) = call(format!("{url}/api/filings?cik=320193&form=annual")).await;
    assert_eq!(v["filings"].as_array().unwrap().len(), 1);
    assert_eq!(v["filings"][0]["form"], "10-K");
    let (_, v) = call(format!("{url}/api/latest?cik=320193")).await;
    assert!(v["latest"]["8-K"].is_object() && v["latest"]["10-Q"].is_object());
    assert_eq!(fake.hits.load(Ordering::SeqCst), before, "submissions are served from the cache");
    let (code, v) = call(format!("{url}/api/facts?cik=320193&metric=assets")).await;
    assert_eq!(code, 200);
    assert_eq!(v["series"][0]["value"], 359241000000.0);
    let (_, v) = call(format!("{url}/api/exhibit21?cik=320193")).await;
    assert_eq!(v["exhibit21_url"], "https://www.sec.gov/Archives/edgar/data/320193/000032019325000079/ex21.htm");
    let (_, v) = call(format!("{url}/api/company?q=apple")).await;
    assert_eq!(v["company"]["cik"], "0000320193");
}

#[tokio::test(flavor = "multi_thread")]
async fn validation_and_error_paths() {
    let (url, _) = start_app(Some("tester@example.org"), true).await;
    for bad_url in ["/api/company?cik=abc", "/api/filings?cik=1&form=%3Cscript%3E", "/api/facts?cik=320193&metric=bogus", "/api/search?q=", "/api/company"] {
        let (code, v) = call(format!("{url}{bad_url}")).await;
        assert_eq!(code, 400, "{bad_url}");
        assert!(v["error"].is_string());
    }
    let (code, _) = call(format!("{url}/api/company?cik=999")).await;
    assert_eq!(code, 404);
    let (code, v) = call(format!("{url}/api/company?cik=1214156")).await;
    assert_eq!(code, 403, "individual filers get no page");
    assert!(v["error"].as_str().unwrap().contains("person pages"));
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_403_is_reported_without_leaking_urls() {
    // A contact the fake rejects stands in for SEC refusing an undeclared client.
    let (url, _) = start_app(Some("other-person@example.org"), true).await;
    let (code, v) = call(format!("{url}/api/company?cik=320193")).await;
    assert_eq!(code, 502);
    let msg = v["error"].as_str().unwrap();
    assert!(msg.contains("403") && !msg.contains("127.0.0.1"), "{msg}");
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_is_enforced_unless_open() {
    let (url, _) = start_app(Some("tester@example.org"), false).await;
    let (code, _) = call(format!("{url}/api/status")).await;
    assert_eq!(code, 401);
    let (code, _) = call(format!("{url}/tools")).await;
    assert_eq!(code, 200, "tool definitions and the page stay open");
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_describe_three_operations() {
    let (url, _) = start_app(None, true).await;
    let (_, v) = call(format!("{url}/tools")).await;
    let names: Vec<&str> = v.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["sec_company", "sec_filings", "sec_facts"]);
    assert!(!v.to_string().to_lowercase().contains("sec_contact"), "no credential names in tool text");
}
