use super::*;
use axum::http::StatusCode;
use axum::{
    extract::{Path, RawQuery, State as AState},
    routing::{get as aget, post as apost},
};
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};

struct Fake {
    hits: AtomicUsize,
    bodies: Mutex<Vec<String>>,
    queries: Mutex<Vec<String>>,
    ted_fail: bool,
}
type S = AState<Arc<Fake>>;

async fn start(ted_fail: bool, open: bool) -> (String, Arc<Fake>) {
    let f = Arc::new(Fake { hits: AtomicUsize::new(0), bodies: Mutex::new(vec![]), queries: Mutex::new(vec![]), ted_fail });
    let r = Router::new()
        .route("/usa/search/spending_over_time/", apost(|AState(f): S, body: String| async move {
            f.hits.fetch_add(1, Ordering::SeqCst);
            f.bodies.lock().unwrap().push(body);
            Json(json!({ "results": [{ "time_period": { "fiscal_year": "2024" }, "aggregated_amount": 100.0 }, { "time_period": { "fiscal_year": "2025" }, "aggregated_amount": 250.5 }] }))
        }))
        .route("/usa/search/spending_by_category/awarding_agency/", apost(|| async { Json(json!({ "results": [{ "name": "Department of Defense", "amount": 300.0 }] })) }))
        .route("/usa/search/spending_by_award/", apost(|| async { Json(json!({ "results": [{ "Award ID": "N0001", "Recipient Name": "LOCKHEED MARTIN CORP", "Award Amount": 99.0, "Awarding Agency": "DoD", "Start Date": "2024-01-01", "Description": format!("{} end", "long ".repeat(80)), "generated_internal_id": "CONT_AWD_N0001_9700_-NONE-_-NONE-" }] })) }))
        .route("/usa/autocomplete/recipient/", apost(|| async { Json(json!({ "results": [{ "recipient_name": "LOCKHEED MARTIN CORPORATION" }] })) }))
        .route("/pp/search.json", aget(|| async { Json(json!({ "total_results": 190, "organizations": [{ "ein": 530196605u64, "name": "American National Red Cross", "city": "Washington", "state": "DC", "ntee_code": "P210", "sub_name": "x" }] })) }))
        .route("/pp/organizations/{ein}", aget(|Path(e): Path<String>| async move {
            use axum::response::IntoResponse;
            if e != "530196605.json" { return StatusCode::NOT_FOUND.into_response(); }
            Json(json!({ "organization": { "name": "American National Red Cross", "careofname": "JOHN PRIVATE", "address": "431 18TH ST NW", "zipcode": "20006", "city": "Washington", "state": "DC", "ntee_code": "P210", "asset_amount": 5000, "income_amount": 4000, "revenue_amount": 3900 },
                "filings_with_data": [{ "tax_prd_yr": 2023, "totrevenue": 3200, "totfuncexpns": 2900, "totassetsend": 4000, "totliabend": 1000, "pct_compnsatncurrofcr": 0.1, "pdf_url": "https://projects.propublica.org/nonprofits/download-filing?path=x" },
                                       { "tax_prd_yr": 2022, "totrevenue": 3000, "totfuncexpns": 2800, "totassetsend": 3900, "totliabend": 900, "pdf_url": "https://evil.example/x.pdf" }] })).into_response()
        }))
        .route("/lda/filings/", aget(|AState(f): S, RawQuery(q): RawQuery| async move {
            let q = q.unwrap_or_default();
            f.queries.lock().unwrap().push(q.clone());
            if q.contains("page_size=1") && !q.contains("page_size=15") { return Json(json!({ "count": 7, "results": [] })); }
            Json(json!({ "count": 40, "results": [{ "filing_type_display": "1st Quarter - Report", "filing_period_display": "1st Quarter (Jan 1 - Mar 31)", "filing_year": 2025, "income": "30000.00", "expenses": null, "dt_posted": "2025-04-01T14:14:04-04:00",
                "filing_document_url": "https://lda.gov/filings/public/filing/abc/print/", "registrant": { "name": "ETHERTON AND ASSOCIATES, INC.", "contact_name": "NELL DILLARD", "contact_telephone": "+1 703" }, "client": { "name": "LOCKHEED MARTIN CORPORATION" }, "posted_by_name": "Nell Dillard",
                "lobbying_activities": [{ "general_issue_code_display": "Defense", "lobbyists": [{ "lobbyist": { "first_name": "PRIVATE", "last_name": "PERSON" } }] }, { "general_issue_code_display": "Defense" }, { "general_issue_code_display": "Budget/Appropriations" }] }] }))
        }))
        .route("/ted/notices/search", apost(|AState(f): S, body: String| async move {
            f.bodies.lock().unwrap().push(body.clone());
            if f.ted_fail { return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))); }
            if body.contains("\"limit\":1,") { return (StatusCode::OK, Json(json!({ "totalNoticeCount": 3, "notices": [] }))); }
            (StatusCode::OK, Json(json!({ "totalNoticeCount": 104, "notices": [{ "publication-number": "384507-2016", "notice-type": "can-standard", "publication-date": "2016-11-02+01:00", "buyer-name": { "deu": ["SBK Siemens-Betriebskrankenkasse"] },
                "winner-name": { "est": ["Siemens Healthcare Oy Eesti filiaal"] }, "notice-title": { "deu": "Datenbank", "eng": "Database services" } }, { "publication-number": "../evil", "notice-title": { "eng": "x" } }] })))
        }))
        .with_state(f.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    let b = Bases { usa: format!("{base}/usa"), propublica: format!("{base}/pp"), lda: format!("{base}/lda"), ted: format!("{base}/ted") };
    let st = new_state(b, open, None, Duration::from_millis(1));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    (url, f)
}

async fn call(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}

#[test]
fn helpers() {
    assert!(valid_org("Lockheed Martin").is_ok());
    assert_eq!(valid_org("  a   b ").unwrap(), "a b");
    for bad in ["", "x", "say \"hi\"", "back\\slash", "ctl\u{7}char", &"a".repeat(101)] {
        assert!(valid_org(bad).is_err(), "{bad:?}");
    }
    assert_eq!(valid_ein("53-0196605").as_deref(), Some("530196605"));
    assert!(valid_ein("12345").is_none() && valid_ein("53019660x").is_none());
    assert_eq!(fiscal_year_bounds(0, 2025, 11), ("2025-10-01".into(), "2026-09-30".into()));
    assert_eq!(fiscal_year_bounds(4, 2025, 3), ("2020-10-01".into(), "2025-09-30".into()));
    assert!((1..=12).contains(&month_now()));
    assert_eq!(clip("a  b   c", 10), "a b c");
    assert!(clip(&"x".repeat(50), 10).ends_with('…'));
}

#[tokio::test(flavor = "multi_thread")]
async fn awards_restrict_recipient_categories_and_cache() {
    let (url, f) = start(false, true).await;
    let (c, v) = call(format!("{url}/api/awards?org=lockheed%20martin&years=3")).await;
    assert_eq!(c, 200);
    assert_eq!(v["total"], 350.5);
    assert_eq!(v["by_fiscal_year"][1]["fiscal_year"], "2025");
    assert_eq!(v["agencies"][0]["name"], "Department of Defense");
    assert_eq!(v["top_awards"][0]["url"], "https://www.usaspending.gov/award/CONT_AWD_N0001_9700_-NONE-_-NONE-");
    assert!(v["top_awards"][0]["description"].as_str().unwrap().chars().count() <= 161);
    assert_eq!(v["matched_recipients"][0], "LOCKHEED MARTIN CORPORATION");
    let body = f.bodies.lock().unwrap()[0].clone();
    assert!(body.contains("category_business") && body.contains("category_nonprofit") && !body.contains("individual"), "{body}");
    assert!(body.contains("\"A\"") && !body.contains("\"02\""));
    let n = f.hits.load(Ordering::SeqCst);
    call(format!("{url}/api/awards?org=LOCKHEED%20MARTIN&years=3")).await;
    assert_eq!(f.hits.load(Ordering::SeqCst), n, "cached");
    call(format!("{url}/api/awards?org=x%20corp&kind=grants")).await;
    assert!(f.bodies.lock().unwrap().last().unwrap().contains("\"02\""));
    for q in ["org=", "org=a", "org=say%20%22hi%22", "org=acme&kind=loans"] {
        assert_eq!(call(format!("{url}/api/awards?{q}")).await.0, 400, "{q}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nonprofit_omits_people_and_addresses() {
    let (url, _) = start(false, true).await;
    let (c, v) = call(format!("{url}/api/nonprofit?q=red%20cross")).await;
    assert_eq!((c, v["organizations"][0]["ein"].clone()), (200, json!("530196605")));
    let (c, v) = call(format!("{url}/api/nonprofit?ein=53-0196605")).await;
    assert_eq!(c, 200);
    assert_eq!(v["filings"][0]["year"], 2022, "sorted oldest first");
    assert!(v["filings"][1]["pdf_url"].is_string() && v["filings"][0]["pdf_url"].is_null(), "off-site pdf links dropped");
    let txt = v.to_string();
    for banned in ["JOHN PRIVATE", "431 18TH", "20006", "pct_comp"] {
        assert!(!txt.contains(banned), "{banned}");
    }
    assert_eq!(call(format!("{url}/api/nonprofit?ein=111111111")).await.0, 404);
    assert_eq!(call(format!("{url}/api/nonprofit?ein=12")).await.0, 400);
    assert_eq!(call(format!("{url}/api/nonprofit")).await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn lobbying_hides_people() {
    let (url, _) = start(false, true).await;
    let (c, v) = call(format!("{url}/api/lobbying?org=lockheed&year=2025")).await;
    assert_eq!(c, 200);
    assert_eq!((v["count"].clone(), v["shown"].clone(), v["partial"].clone()), (json!(40), json!(1), json!(true)));
    assert_eq!(v["filings"][0]["issues"], json!(["Budget/Appropriations", "Defense"]));
    assert_eq!(v["filings"][0]["income"], 30000.0);
    assert_eq!(v["by_year"].as_array().unwrap().len(), 5);
    let txt = v.to_string();
    for banned in ["NELL", "DILLARD", "Dillard", "PRIVATE", "+1 703"] {
        assert!(!txt.contains(banned), "{banned}");
    }
    for q in ["org=lockheed&year=1980", "org=lockheed&year=abc", "org=lockheed&year=2999"] {
        assert_eq!(call(format!("{url}/api/lobbying?{q}")).await.0, 400, "{q}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tenders_and_upstream_failure() {
    let (url, f) = start(false, true).await;
    let (c, v) = call(format!("{url}/api/tenders?org=siemens&role=winner")).await;
    assert_eq!(c, 200);
    assert_eq!(v["total"], 104);
    assert_eq!(v["notices"][0]["title"], "Database services");
    assert_eq!(v["notices"][0]["winner"], "Siemens Healthcare Oy Eesti filiaal");
    assert_eq!(v["notices"][0]["published"], "2016-11-02");
    assert_eq!(v["notices"][0]["url"], "https://ted.europa.eu/en/notice/-/detail/384507-2016");
    assert!(v["notices"][1]["url"].is_null(), "odd ids get no link");
    assert_eq!(v["by_year"].as_array().unwrap().len(), 6);
    assert!(f.bodies.lock().unwrap().iter().any(|b| b.contains("winner-name=\\\"siemens\\\"")));
    assert_eq!(call(format!("{url}/api/tenders?org=siemens&role=boss")).await.0, 400);
    let (url, _) = start(true, true).await;
    let (c, v) = call(format!("{url}/api/tenders?org=siemens")).await;
    assert_eq!(c, 502);
    assert!(!v["error"].as_str().unwrap().contains("127.0.0.1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_and_tools() {
    let (url, _) = start(false, false).await;
    assert_eq!(call(format!("{url}/api/awards?org=acme")).await.0, 401);
    let (_, v) = call(format!("{url}/tools")).await;
    assert_eq!(v.as_array().unwrap().len(), 4);
}
