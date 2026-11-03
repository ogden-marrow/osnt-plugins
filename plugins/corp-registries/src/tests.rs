use super::*;
use axum::{
    extract::{Path, RawQuery, State as AState},
    http::HeaderMap,
    routing::{get as aget, post as apost},
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fake {
    hits: AtomicUsize,
    brreg_fail: bool,
    sparql: Mutex<Vec<String>>,
    auth: Mutex<Vec<String>>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) { out.push(v); i += 3; continue; }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn gleif_rec(lei: &str, name: &str, cat: &str) -> Value {
    json!({ "id": lei, "attributes": { "entity": { "category": cat, "status": "ACTIVE", "jurisdiction": "DE", "creationDate": "1996-08-27T22:00:00Z", "legalName": { "name": name },
        "legalAddress": { "addressLines": ["Werner-von-Siemens-Str. 1"], "postalCode": "80333", "city": "München", "country": "DE" }, "headquartersAddress": { "addressLines": ["HQ 1"], "city": "München", "country": "DE" },
        "registeredAs": "HRB 6684", "registeredAt": { "id": "RA000304" }, "legalForm": { "id": "6QQB" }, "otherNames": [{ "name": "Siemens AG" }] },
        "registration": { "status": "ISSUED", "lastUpdateDate": "2026-09-01T00:00:00Z" } } })
}
const LEI: &str = "W38RGI023J3WT1HWRP32";
const PARENT: &str = "5299005CHJZ14D4FDJ62";
const SOLE: &str = "SOLE000000000000000A";

async fn start(brreg_fail: bool, keys: bool, open: bool) -> (String, Arc<Fake>) {
    let f = Arc::new(Fake { hits: AtomicUsize::new(0), brreg_fail, sparql: Mutex::new(vec![]), auth: Mutex::new(vec![]) });
    type S = AState<Arc<Fake>>;
    let r = Router::new()
        .route("/gleif/lei-records", aget(|AState(f): S| async move {
            f.hits.fetch_add(1, Ordering::SeqCst);
            Json(json!({ "data": [gleif_rec(LEI, "Siemens Aktiengesellschaft", "GENERAL"), gleif_rec(SOLE, "Hans Mueller", "SOLE_PROPRIETOR")] }))
        }))
        .route("/gleif/lei-records/{lei}", aget(|AState(f): S, Path(l): Path<String>| async move {
            f.hits.fetch_add(1, Ordering::SeqCst);
            match l.as_str() { LEI => Json(json!({ "data": gleif_rec(LEI, "Siemens Aktiengesellschaft", "GENERAL") })).into_response(), SOLE => Json(json!({ "data": gleif_rec(SOLE, "Hans Mueller", "SOLE_PROPRIETOR") })).into_response(), _ => StatusCode::NOT_FOUND.into_response() }
        }))
        .route("/gleif/lei-records/{lei}/{rel}", aget(|Path((l, rel)): Path<(String, String)>| async move {
            use axum::response::IntoResponse;
            match (l.as_str(), rel.as_str()) {
                (LEI, "direct-parent") => Json(json!({ "data": gleif_rec(PARENT, "Parent Holding AG", "GENERAL") })).into_response(),
                (LEI, "direct-children") => Json(json!({ "data": [gleif_rec("CHILD0000000000000001", "Siemens Mobility GmbH", "GENERAL"), gleif_rec(SOLE, "Hans Mueller", "SOLE_PROPRIETOR")], "meta": { "pagination": { "total": 461 } } })).into_response(),
                (LEI, "ultimate-parent-reporting-exception") => Json(json!({ "data": { "attributes": { "reason": "NO_KNOWN_PERSON" } } })).into_response(),
                (LEI, "direct-parent-reporting-exception") => StatusCode::NOT_FOUND.into_response(),
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }))
        .route("/wdapi", aget(|| async { Json(json!({ "search": [{ "id": "Q81230", "label": "Siemens", "description": "German conglomerate" }, { "id": "Q16883318", "label": "Siemens", "description": "family name" }] })) }))
        .route("/sparql", aget(|AState(f): S, RawQuery(q): RawQuery| async move {
            let q = q.unwrap_or_default();
            let dec = pct_decode(&q);
            f.sparql.lock().unwrap().push(dec.clone());
            let uri = |id: &str| json!({ "type": "uri", "value": format!("http://www.wikidata.org/entity/{id}") });
            let b = if dec.contains("VALUES") { json!([{ "c": uri("Q81230") }]) }
                else if dec.contains("P1278") && dec.contains("SELECT ?c") { json!([{ "c": uri("Q81230") }]) }
                else if dec.contains("?rel") { json!([{ "rel": {"value": "subsidiary"}, "o": uri("Q391895"), "oLabel": {"value": "Siemens Mobility"} }, { "rel": {"value": "owned_by"}, "o": uri("Q219635"), "oLabel": {"value": "BlackRock"} }, { "rel": {"value": "owned_by"}, "o": {"value": "javascript:evil"}, "oLabel": {"value": "bad"} }]) }
                else { json!([{ "website": {"value": "https://www.siemens.com/"}, "inception": {"value": "1847-10-01T00:00:00Z"}, "hqLabel": {"value": "Munich"} }]) };
            Json(json!({ "results": { "bindings": b } }))
        }))
        .route("/brreg/enheter", aget(|AState(f): S| async move {
            if f.brreg_fail { return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))); }
            (StatusCode::OK, Json(json!({ "_embedded": { "enheter": [
                { "organisasjonsnummer": "923609016", "navn": "EQUINOR ASA", "organisasjonsform": { "kode": "ASA", "beskrivelse": "Allmennaksjeselskap" } },
                { "organisasjonsnummer": "1", "navn": "OLA NORDMANN", "organisasjonsform": { "kode": "ENK", "beskrivelse": "Enkeltpersonforetak" } }] } })))
        }))
        .route("/ares/vyhledat", apost(|| async { Json(json!({ "ekonomickeSubjekty": [{ "ico": "00177041", "obchodniJmeno": "Škoda Auto a.s.", "pravniForma": "121" }, { "ico": "2", "obchodniJmeno": "Jan Novák", "pravniForma": "101" }] })) }))
        .route("/prh", aget(|| async { Json(json!({ "companies": [{ "businessId": { "value": "0112038-9" }, "names": [{ "name": "Nokia Oyj", "type": "1", "endDate": null }], "companyForms": [{ "type": "17", "descriptions": [{ "languageCode": "3", "description": "Public limited company" }] }] }] })) }))
        .route("/cvr", aget(|| async { Json(json!({ "vat": 24256790, "name": "NOVO NORDISK A/S", "companydesc": "Aktieselskab", "owners": [{ "name": "SECRET PERSON" }] })) }))
        .route("/ch/search/companies", aget(|AState(f): S, h: HeaderMap| async move {
            f.auth.lock().unwrap().push(h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string());
            Json(json!({ "items": [{ "company_number": "00000006", "title": "MARINE AND GENERAL", "company_status": "active" }] }))
        }))
        .route("/oc/companies/search", aget(|| async { Json(json!({ "results": { "companies": [{ "company": { "name": "GITHUB, INC.", "company_number": "5272062", "jurisdiction_code": "us_de", "opencorporates_url": "https://opencorporates.com/companies/us_de/5272062" } }] } })) }))
        .route("/aleph/entities", aget(|| async { Json(json!({ "results": [{ "id": "abc", "schema": "Company", "caption": "Acme Ltd" }, { "id": "def", "schema": "Person", "caption": "Some Person" }] })) }))
        .with_state(f.clone());
    use axum::response::IntoResponse as _;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    let b = Bases { gleif: format!("{base}/gleif"), wd_api: format!("{base}/wdapi"), wd_sparql: format!("{base}/sparql"), brreg: format!("{base}/brreg"), ares: format!("{base}/ares"),
        prh: format!("{base}/prh"), cvr: format!("{base}/cvr"), ch: format!("{base}/ch"), oc: format!("{base}/oc"), aleph: format!("{base}/aleph") };
    let st = new_state(b, open, None, Box::new(move |n| keys.then(|| format!("secret-{}", n.to_lowercase()))));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app(st)).await.unwrap() });
    (url, f)
}
use axum::response::IntoResponse;

async fn call(url: String) -> (u16, Value) {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        let mut r = agent.get(&url).call().unwrap();
        (r.status().as_u16(), r.body_mut().read_json::<Value>().unwrap_or(Value::Null))
    })
    .await
    .unwrap()
}
fn src<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["sources"].as_array().unwrap().iter().find(|s| s["source"] == id).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn search_merges_sources_and_hides_individuals() {
    let (url, _) = start(false, true, true).await;
    let (c, v) = call(format!("{url}/api/search?q=siemens")).await;
    assert_eq!(c, 200);
    assert_eq!(v["sources"].as_array().unwrap().len(), 9);
    let g = src(&v, "gleif");
    assert_eq!(g["items"].as_array().unwrap().len(), 1);
    assert_eq!(g["hidden_individuals"], 1);
    assert_eq!(src(&v, "wikidata")["items"].as_array().unwrap().len(), 1, "family name item removed by the organisation check");
    assert_eq!(src(&v, "brreg")["hidden_individuals"], 1);
    assert_eq!(src(&v, "ares")["items"][0]["name"], "Škoda Auto a.s.");
    assert_eq!(src(&v, "ares")["hidden_individuals"], 1);
    assert_eq!(src(&v, "prh")["items"][0]["form"], "Public limited company");
    assert_eq!(src(&v, "cvr")["items"][0]["id"], "24256790");
    assert_eq!(src(&v, "companies-house")["items"][0]["id"], "00000006");
    assert_eq!(src(&v, "opencorporates")["items"][0]["id"], "us_de/5272062");
    assert_eq!(src(&v, "aleph")["items"].as_array().unwrap().len(), 1);
    let txt = v.to_string();
    for banned in ["SECRET PERSON", "Hans Mueller", "OLA NORDMANN", "Jan Novák", "secret-", "Some Person"] {
        assert!(!txt.contains(banned), "{banned} leaked");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn keyed_sources_skip_without_keys_and_send_auth_when_set() {
    let (url, f) = start(false, false, true).await;
    let (_, v) = call(format!("{url}/api/search?q=acme&sources=companies-house,aleph,gleif")).await;
    assert_eq!(src(&v, "companies-house")["skipped"], "no key configured");
    assert_eq!(src(&v, "gleif")["ok"], true);
    assert!(f.auth.lock().unwrap().is_empty());
    let (url, f) = start(false, true, true).await;
    call(format!("{url}/api/search?q=acme&sources=companies-house")).await;
    assert_eq!(f.auth.lock().unwrap()[0], format!("Basic {}", sources::b64(b"secret-companies_house_api_key:")));
    let (_, s) = call(format!("{url}/api/status")).await;
    assert!(s.to_string().contains("\"key_set\":true") && !s.to_string().contains("secret-"));
}

#[tokio::test(flavor = "multi_thread")]
async fn one_failing_source_does_not_break_the_rest() {
    let (url, _) = start(true, false, true).await;
    let (c, v) = call(format!("{url}/api/search?q=siemens&sources=brreg,gleif")).await;
    assert_eq!(c, 200);
    let b = src(&v, "brreg");
    assert_eq!(b["ok"], false);
    assert!(b["error"].as_str().unwrap().contains("500") && !b["error"].as_str().unwrap().contains("127.0.0.1"));
    assert_eq!(src(&v, "gleif")["ok"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn validation() {
    let (url, _) = start(false, false, true).await;
    for q in ["q=", "q=a", "q=siemens&sources=evil", &format!("q={}", "a".repeat(101))] {
        assert_eq!(call(format!("{url}/api/search?{q}")).await.0, 400, "{q}");
    }
    for q in ["lei=short", "lei=", "lei=w38rgi023j3wt1hwrp3!"] {
        assert_eq!(call(format!("{url}/api/lei?{q}")).await.0, 400, "{q}");
    }
    assert_eq!(call(format!("{url}/api/ownership")).await.0, 400);
    assert_eq!(call(format!("{url}/api/ownership?qid=Q1%3BDROP")).await.0, 400);
    assert_eq!(call(format!("{url}/api/ownership?lei=ZZZZZZZZZZZZZZZZZZZZ")).await.0, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn lei_record_and_sole_proprietor_refusal() {
    let (url, _) = start(false, false, true).await;
    let (c, v) = call(format!("{url}/api/lei?lei={}", LEI.to_lowercase())).await;
    assert_eq!(c, 200);
    assert_eq!(v["legal_name"], "Siemens Aktiengesellschaft");
    assert_eq!(v["registered_as"], "HRB 6684");
    assert!(v["legal_address"].as_str().unwrap().contains("München"));
    assert_eq!(call(format!("{url}/api/lei?lei={SOLE}")).await.0, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn ownership_combines_gleif_and_wikidata() {
    let (url, f) = start(false, false, true).await;
    let (c, v) = call(format!("{url}/api/ownership?lei={LEI}")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["gleif"]["direct_parent"]["parent"]["name"], "Parent Holding AG");
    assert!(v["gleif"]["ultimate_parent"]["parent"].is_null());
    assert_eq!(v["gleif"]["ultimate_parent"]["reason"], "no known person");
    assert_eq!(v["gleif"]["children"].as_array().unwrap().len(), 1, "sole proprietor child dropped");
    assert_eq!(v["gleif"]["children_total"], 461);
    assert_eq!(v["qid"], "Q81230");
    assert_eq!(v["wikidata"]["subsidiaries"][0]["name"], "Siemens Mobility");
    assert_eq!(v["wikidata"]["owned_by"].as_array().unwrap().len(), 1, "malformed entity ids are dropped");
    assert_eq!(v["wikidata"]["headquarters"], "Munich");
    let queries = f.sparql.lock().unwrap().join("\n");
    assert!(queries.contains("wdt:P31 wd:Q5") && queries.contains("Q8436"), "human and family exclusion filters are sent");
    let (_, v) = call(format!("{url}/api/ownership?qid=Q81230")).await;
    assert!(v["gleif"].is_null() && v["wikidata"]["qid"] == "Q81230");
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_are_cached() {
    let (url, f) = start(false, false, true).await;
    call(format!("{url}/api/search?q=siemens&sources=gleif")).await;
    call(format!("{url}/api/search?q=Siemens&sources=gleif")).await;
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_and_tools() {
    let (url, _) = start(false, false, false).await;
    assert_eq!(call(format!("{url}/api/search?q=siemens")).await.0, 401);
    let (_, v) = call(format!("{url}/tools")).await;
    assert_eq!(v.as_array().unwrap().len(), 3);
    assert!(!v.to_string().contains("API_KEY"));
}

#[test]
fn gleif_ranking_puts_the_plain_company_before_funds() {
    let mk = |n: &str| Card { source: "gleif", id: n.into(), name: n.into(), status: None, form: None, address: None, founded: None, industry: None, country: None, url: String::new(), parent: None };
    let mut v = vec![mk("VERDIPAPIRFONDET EQUINOR AKSJER USA INDEKS"), mk("ADURA ENERGY LIMITED"), mk("Equinor Fond"), mk("EQUINOR ASA")];
    rank_gleif(&mut v, "equinor");
    let names: Vec<&str> = v.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names[0], "EQUINOR ASA");
    assert_eq!(names[3], "ADURA ENERGY LIMITED");
}
