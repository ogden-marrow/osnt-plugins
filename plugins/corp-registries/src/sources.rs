//! Parsers that turn each registry's JSON into one company-level card shape. Individuals are filtered out here:
//! sole proprietors, sole traders and records a registry marks as protected are never returned, and officers,
//! directors, owners and shareholders are never read.

use serde_json::{Value, json};

fn s(v: &Value) -> Option<String> {
    match v {
        Value::String(x) => Some(x.trim().to_string()).filter(|x| !x.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub struct Card {
    pub source: &'static str,
    pub id: String,
    pub name: String,
    pub status: Option<String>,
    pub form: Option<String>,
    pub address: Option<String>,
    pub founded: Option<String>,
    pub industry: Option<String>,
    pub country: Option<String>,
    pub url: String,
    pub parent: Option<String>,
}
impl Card {
    pub fn json(self) -> Value {
        json!({ "source": self.source, "id": self.id, "name": self.name, "status": self.status, "form": self.form, "address": self.address,
            "founded": self.founded, "industry": self.industry, "country": self.country, "url": self.url, "parent": self.parent })
    }
}

fn join(parts: &[Option<String>]) -> Option<String> {
    let p: Vec<String> = parts.iter().flatten().cloned().collect();
    (!p.is_empty()).then(|| p.join(", "))
}

pub fn valid_lei(x: &str) -> bool {
    x.len() == 20 && x.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
pub fn valid_qid(x: &str) -> bool {
    x.len() > 1 && x.len() < 14 && x.starts_with('Q') && x[1..].bytes().all(|b| b.is_ascii_digit())
}

/// GLEIF lei-records entry -> card; None for sole proprietors.
pub fn gleif_card(r: &Value) -> Option<Card> {
    let e = &r["attributes"]["entity"];
    if e["category"].as_str() == Some("SOLE_PROPRIETOR") {
        return None;
    }
    let a = &e["legalAddress"];
    Some(Card {
        source: "gleif",
        id: s(&r["id"])?,
        name: s(&e["legalName"]["name"])?,
        status: s(&e["status"]),
        form: s(&e["category"]).map(|c| c.to_lowercase().replace('_', " ")),
        address: join(&[a["addressLines"].as_array().and_then(|l| l.first()).and_then(s), s(&a["postalCode"]), s(&a["city"]), s(&a["country"])]),
        founded: s(&e["creationDate"]).map(|d| d.chars().take(10).collect()),
        industry: None,
        country: s(&e["jurisdiction"]),
        url: format!("https://search.gleif.org/#/record/{}", r["id"].as_str()?),
        parent: None,
    })
}

pub fn brreg_card(u: &Value) -> Option<Card> {
    if u["organisasjonsform"]["kode"].as_str() == Some("ENK") {
        return None; // sole proprietorship: an individual
    }
    let a = &u["forretningsadresse"];
    let id = s(&u["organisasjonsnummer"])?;
    Some(Card {
        source: "brreg",
        name: s(&u["navn"])?,
        status: Some(if u["konkurs"].as_bool() == Some(true) { "bankrupt" } else if u["underAvvikling"].as_bool() == Some(true) || u["underTvangsavviklingEllerTvangsopplosning"].as_bool() == Some(true) { "being wound up" } else { "active" }.to_string()),
        form: s(&u["organisasjonsform"]["beskrivelse"]),
        address: join(&[a["adresse"].as_array().and_then(|l| l.first()).and_then(s), s(&a["postnummer"]), s(&a["poststed"]), s(&a["land"])]),
        founded: s(&u["stiftelsesdato"]).or_else(|| s(&u["registreringsdatoEnhetsregisteret"])),
        industry: s(&u["naeringskode1"]["beskrivelse"]).map(|d| match s(&u["naeringskode1"]["kode"]) { Some(k) => format!("{d} ({k})"), None => d }),
        country: Some("NO".into()),
        url: format!("https://virksomhet.brreg.no/oppslag/enheter/{id}"),
        parent: s(&u["overordnetEnhet"]).map(|p| format!("org. no. {p}")),
        id,
    })
}

/// Czech legal forms 100 to 109 are natural persons (sole traders); everything from 110 up is a legal entity.
pub fn ares_is_individual(form: &str) -> bool {
    form.parse::<u32>().is_ok_and(|n| (100..110).contains(&n))
}
pub fn ares_card(u: &Value) -> Option<Card> {
    let form = s(&u["pravniForma"]).unwrap_or_default();
    if ares_is_individual(&form) {
        return None;
    }
    let id = s(&u["ico"])?;
    Some(Card {
        source: "ares",
        name: s(&u["obchodniJmeno"])?,
        status: s(&u["seznamRegistraci"]["stavZdrojeVr"]).map(|x| x.to_lowercase()),
        form: (!form.is_empty()).then(|| format!("legal form {form}")),
        address: s(&u["sidlo"]["textovaAdresa"]),
        founded: s(&u["datumVzniku"]),
        industry: None,
        country: Some("CZ".into()),
        url: format!("https://ares.gov.cz/ekonomicke-subjekty?ico={id}"),
        parent: None,
        id,
    })
}

fn lang_text(v: &Value, pref: &[&str]) -> Option<String> {
    let arr = v.as_array()?;
    for l in pref {
        if let Some(d) = arr.iter().find(|d| d["languageCode"].as_str() == Some(l)) {
            return s(&d["description"]);
        }
    }
    arr.first().and_then(|d| s(&d["description"]))
}

pub fn prh_is_individual(c: &Value) -> bool {
    c["companyForms"].as_array().is_some_and(|f| f.iter().any(|x| {
        x["type"].as_str() == Some("26") || x["descriptions"].as_array().is_some_and(|d| d.iter().any(|y| {
            let t = y["description"].as_str().unwrap_or("").to_lowercase();
            t.contains("elinkeinonharjoittaja") || t.contains("privatföretagare") || t.contains("private trader") || t.contains("sole trader") || t.contains("toiminimi")
        }))
    }))
}
pub fn prh_card(c: &Value) -> Option<Card> {
    if prh_is_individual(c) {
        return None;
    }
    let id = s(&c["businessId"]["value"])?;
    let names = c["names"].as_array()?;
    let current = names.iter().find(|n| n["endDate"].is_null() && n["type"].as_str() == Some("1")).or_else(|| names.iter().find(|n| n["endDate"].is_null())).or(names.first())?;
    let addr = c["addresses"].as_array().and_then(|a| a.iter().find(|x| x["type"].as_i64() == Some(1)));
    let address = addr.and_then(|a| join(&[
        join(&[s(&a["street"]), s(&a["buildingNumber"])]).map(|x| x.replace(", ", " ")),
        s(&a["postCode"]),
        a["postOffices"].as_array().and_then(|p| p.iter().find(|x| x["languageCode"].as_str() == Some("1")).or(p.first())).and_then(|p| s(&p["city"])),
    ]));
    Some(Card {
        source: "prh",
        name: s(&current["name"])?,
        status: Some(if c["endDate"].is_null() && !c["companySituations"].as_array().is_some_and(|x| !x.is_empty()) { "active" } else { "ended or in a special situation" }.into()),
        form: c["companyForms"].as_array().and_then(|f| f.first()).and_then(|f| lang_text(&f["descriptions"], &["3", "1"])),
        address,
        founded: s(&c["registrationDate"]),
        industry: lang_text(&c["mainBusinessLine"]["descriptions"], &["3", "1"]),
        country: Some("FI".into()),
        url: format!("https://tietopalvelu.ytj.fi/yritys/{id}"),
        parent: None,
        id,
    })
}

/// cvrapi.dk answers one company. Sole proprietorships and protected records are dropped; `owners` is never read.
pub fn cvr_card(c: &Value) -> Option<Card> {
    if c["protected"].as_bool() == Some(true) {
        return None;
    }
    let form = s(&c["companydesc"]).unwrap_or_default();
    let fl = form.to_lowercase();
    if fl.contains("enkeltmand") || fl.contains("personligt") {
        return None;
    }
    let id = s(&c["vat"])?;
    Some(Card {
        source: "cvr",
        name: s(&c["name"])?,
        status: Some(if c["enddate"].is_null() { "active" } else { "ended" }.into()),
        form: Some(form).filter(|f| !f.is_empty()),
        address: join(&[s(&c["address"]), s(&c["zipcode"]), s(&c["city"])]),
        founded: s(&c["startdate"]),
        industry: s(&c["industrydesc"]),
        country: Some("DK".into()),
        url: format!("https://datacvr.virk.dk/enhed/virksomhed/{id}"),
        parent: None,
        id,
    })
}

pub fn ch_card(c: &Value) -> Option<Card> {
    let id = s(&c["company_number"])?;
    Some(Card {
        source: "companies-house",
        name: s(&c["title"])?,
        status: s(&c["company_status"]),
        form: s(&c["company_type"]),
        address: s(&c["address_snippet"]),
        founded: s(&c["date_of_creation"]),
        industry: None,
        country: Some("GB".into()),
        url: format!("https://find-and-update.company-information.service.gov.uk/company/{id}"),
        parent: None,
        id,
    })
}

pub fn oc_card(c: &Value) -> Option<Card> {
    let c = &c["company"];
    let id = s(&c["company_number"])?;
    let jur = s(&c["jurisdiction_code"]).unwrap_or_default();
    Some(Card {
        source: "opencorporates",
        name: s(&c["name"])?,
        status: s(&c["current_status"]),
        form: s(&c["company_type"]),
        address: s(&c["registered_address_in_full"]),
        founded: s(&c["incorporation_date"]),
        industry: None,
        country: Some(jur.to_uppercase()).filter(|j| !j.is_empty()),
        url: s(&c["opencorporates_url"]).filter(|u| u.starts_with("https://opencorporates.com/"))?,
        parent: None,
        id: format!("{jur}/{id}"),
    })
}

pub fn aleph_card(e: &Value) -> Option<Card> {
    let schema = e["schema"].as_str()?;
    if !matches!(schema, "Company" | "Organization" | "PublicBody") {
        return None; // never Person or LegalEntity (which may be a person)
    }
    let p = &e["properties"];
    let first = |k: &str| p[k].as_array().and_then(|a| a.first()).and_then(s);
    let id = s(&e["id"])?;
    Some(Card {
        source: "aleph",
        name: s(&e["caption"])?,
        status: first("status"),
        form: Some(schema.to_string()),
        address: None,
        founded: first("incorporationDate"),
        industry: None,
        country: first("jurisdiction").or_else(|| first("country")),
        url: format!("https://aleph.occrp.org/entities/{id}"),
        parent: None,
        id,
    })
}

pub fn b64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_lei("W38RGI023J3WT1HWRP32") && !valid_lei("w38rgi023j3wt1hwrp32") && !valid_lei("SHORT"));
        assert!(valid_qid("Q81230") && !valid_qid("Q") && !valid_qid("81230") && !valid_qid("Q1; DROP"));
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(b64(b"key:"), "a2V5Og==");
        assert_eq!(b64(b"ab"), "YWI=");
        assert_eq!(b64(b"abc"), "YWJj");
        assert_eq!(b64(b""), "");
    }

    #[test]
    fn gleif_hides_sole_proprietors() {
        let ok = json!({ "id": "W38RGI023J3WT1HWRP32", "attributes": { "entity": { "category": "GENERAL", "status": "ACTIVE", "jurisdiction": "DE", "creationDate": "1996-08-27T22:00:00Z",
            "legalName": { "name": "Siemens Aktiengesellschaft" }, "legalAddress": { "addressLines": ["Werner-von-Siemens-Str. 1"], "postalCode": "80333", "city": "München", "country": "DE" } } } });
        let c = gleif_card(&ok).unwrap();
        assert_eq!((c.name.as_str(), c.founded.as_deref()), ("Siemens Aktiengesellschaft", Some("1996-08-27")));
        assert!(c.address.unwrap().contains("München"));
        let mut sole = ok.clone();
        sole["attributes"]["entity"]["category"] = json!("SOLE_PROPRIETOR");
        assert!(gleif_card(&sole).is_none());
    }

    #[test]
    fn registries_drop_individuals() {
        let enk = json!({ "organisasjonsnummer": "1", "navn": "OLA NORDMANN", "organisasjonsform": { "kode": "ENK", "beskrivelse": "Enkeltpersonforetak" } });
        assert!(brreg_card(&enk).is_none());
        let asa = json!({ "organisasjonsnummer": "923609016", "navn": "EQUINOR ASA", "organisasjonsform": { "kode": "ASA", "beskrivelse": "Allmennaksjeselskap" }, "konkurs": false,
            "forretningsadresse": { "adresse": ["Forusbeen 50"], "postnummer": "4035", "poststed": "STAVANGER", "land": "Norge" }, "naeringskode1": { "kode": "06.100", "beskrivelse": "Utvinning av råolje" }, "overordnetEnhet": "999" });
        let c = brreg_card(&asa).unwrap();
        assert_eq!(c.status.as_deref(), Some("active"));
        assert_eq!(c.industry.as_deref(), Some("Utvinning av råolje (06.100)"));
        assert_eq!(c.parent.as_deref(), Some("org. no. 999"));
        assert!(ares_card(&json!({ "ico": "1", "obchodniJmeno": "Jan Novák", "pravniForma": "101" })).is_none());
        assert!(ares_card(&json!({ "ico": "45274649", "obchodniJmeno": "ČEZ, a. s.", "pravniForma": "121", "sidlo": { "textovaAdresa": "Duhová 1444/2" } })).is_some());
        assert!(ares_is_individual("100") && ares_is_individual("109") && !ares_is_individual("110") && !ares_is_individual("x"));
        assert!(cvr_card(&json!({ "vat": 1, "name": "Hans", "companydesc": "Enkeltmandsvirksomhed" })).is_none());
        assert!(cvr_card(&json!({ "vat": 1, "name": "X", "companydesc": "Aktieselskab", "protected": true })).is_none());
        let c = cvr_card(&json!({ "vat": 24256790, "name": "NOVO NORDISK A/S", "companydesc": "Aktieselskab", "address": "Novo Alle 1", "zipcode": "2880", "city": "Bagsværd", "enddate": null, "owners": [{ "name": "PRIVATE PERSON" }] })).unwrap();
        assert!(!c.json().to_string().contains("PRIVATE PERSON"));
    }

    #[test]
    fn prh_form_filter() {
        let sole = json!({ "businessId": { "value": "1234567-8" }, "names": [{ "name": "Matti Meikäläinen Tmi", "type": "1", "endDate": null }], "companyForms": [{ "type": "26", "descriptions": [{ "languageCode": "3", "description": "Sole trader" }] }] });
        assert!(prh_card(&sole).is_none());
        let oyj = json!({ "businessId": { "value": "0112038-9" }, "names": [{ "name": "Old", "type": "1", "endDate": "2020-01-01" }, { "name": "Nokia Oyj", "type": "1", "endDate": null }], "endDate": null, "companySituations": [],
            "companyForms": [{ "type": "17", "descriptions": [{ "languageCode": "1", "description": "Julkinen osakeyhtiö" }, { "languageCode": "3", "description": "Public limited company" }] }],
            "addresses": [{ "type": 1, "street": "Karakaari", "buildingNumber": "7", "postCode": "02610", "postOffices": [{ "city": "ESPOO", "languageCode": "1" }] }], "mainBusinessLine": { "descriptions": [{ "languageCode": "3", "description": "Activities of head offices" }] } });
        let c = prh_card(&oyj).unwrap();
        assert_eq!(c.name, "Nokia Oyj");
        assert_eq!(c.form.as_deref(), Some("Public limited company"));
        assert_eq!(c.address.as_deref(), Some("Karakaari 7, 02610, ESPOO"));
    }

    #[test]
    fn keyed_sources() {
        assert!(ch_card(&json!({ "company_number": "00000006", "title": "MARINE AND GENERAL MUTUAL LIFE ASSURANCE SOCIETY", "company_status": "active", "address_snippet": "Somewhere, London" })).is_some());
        let oc = json!({ "company": { "name": "GITHUB, INC.", "company_number": "5272062", "jurisdiction_code": "us_de", "opencorporates_url": "https://opencorporates.com/companies/us_de/5272062" } });
        assert_eq!(oc_card(&oc).unwrap().id, "us_de/5272062");
        let evil = json!({ "company": { "name": "X", "company_number": "1", "jurisdiction_code": "gb", "opencorporates_url": "https://evil.example/x" } });
        assert!(oc_card(&evil).is_none(), "links must stay on the registry's host");
        assert!(aleph_card(&json!({ "id": "a", "schema": "Person", "caption": "Someone" })).is_none());
        assert!(aleph_card(&json!({ "id": "a", "schema": "LegalEntity", "caption": "Maybe a person" })).is_none());
        assert!(aleph_card(&json!({ "id": "a", "schema": "Company", "caption": "Acme", "properties": { "jurisdiction": ["gb"] } })).is_some());
    }
}
