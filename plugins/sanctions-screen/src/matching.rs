//! Name normalisation and explainable fuzzy matching (token similarity plus a phonetic fallback).

const STOP: &[&str] = &[
    "ltd", "limited", "llc", "inc", "incorporated", "corp", "corporation", "co", "company", "plc", "gmbh", "ag", "sa", "sarl", "srl", "bv", "nv", "oy", "ab", "as", "asa",
    "ooo", "oao", "zao", "pao", "jsc", "ojsc", "cjsc", "pjsc", "llp", "lp", "pte", "pvt", "private", "the", "of", "and", "de", "la", "al", "el", "fze", "fzc", "fzco", "kg", "spa", "sas", "ltda",
];

fn fold(c: char) -> Option<&'static str> {
    Some(match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => "a",
        'ç' | 'ć' | 'č' | 'ĉ' => "c",
        'ď' | 'đ' => "d",
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ę' | 'ě' => "e",
        'ğ' | 'ĝ' => "g",
        'ì' | 'í' | 'î' | 'ï' | 'ī' | 'ı' => "i",
        'ł' | 'ľ' => "l",
        'ñ' | 'ń' | 'ň' => "n",
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => "o",
        'ř' => "r",
        'ś' | 'š' | 'ş' => "s",
        'ť' | 'ţ' => "t",
        'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' => "u",
        'ý' | 'ÿ' => "y",
        'ź' | 'ż' | 'ž' => "z",
        'ß' => "ss",
        'æ' => "ae",
        'œ' => "oe",
        _ => return None,
    })
}

/// Lower-case, fold Latin diacritics, drop punctuation. Non-Latin letters are kept as they are.
pub fn normalise(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(char::to_lowercase) {
        if let Some(f) = fold(c) {
            out.push_str(f);
        } else if c.is_alphanumeric() {
            out.push(c);
        } else {
            out.push(' ');
        }
    }
    out
}

/// Tokens of a name without company-form words; if that would leave nothing, all tokens.
pub fn tokens(s: &str) -> Vec<String> {
    let all: Vec<String> = normalise(s).split_whitespace().map(str::to_string).collect();
    let kept: Vec<String> = all.iter().filter(|t| !STOP.contains(&t.as_str())).cloned().collect();
    if kept.is_empty() { all } else { kept }
}

pub fn soundex(t: &str) -> Option<[u8; 4]> {
    let b: Vec<u8> = t.bytes().filter(|b| b.is_ascii_lowercase()).collect();
    if b.len() < 3 || b.len() != t.len() {
        return None;
    }
    let code = |c: u8| match c {
        b'b' | b'f' | b'p' | b'v' => b'1',
        b'c' | b'g' | b'j' | b'k' | b'q' | b's' | b'x' | b'z' => b'2',
        b'd' | b't' => b'3',
        b'l' => b'4',
        b'm' | b'n' => b'5',
        b'r' => b'6',
        _ => b'0',
    };
    let mut out = [b'0'; 4];
    out[0] = b[0].to_ascii_uppercase();
    let mut last = code(b[0]);
    let mut n = 1;
    for &c in &b[1..] {
        let k = code(c);
        if k != b'0' && k != last && n < 4 {
            out[n] = k;
            n += 1;
        }
        if c != b'h' && c != b'w' {
            last = k;
        }
    }
    Some(out)
}

pub fn jaro_winkler(a: &str, b: &str) -> f64 {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    if a == b {
        return 1.0;
    }
    let window = (a.len().max(b.len()) / 2).saturating_sub(1);
    let (mut am, mut bm) = (vec![false; a.len()], vec![false; b.len()]);
    let mut m = 0usize;
    for i in 0..a.len() {
        let lo = i.saturating_sub(window);
        let hi = (i + window + 1).min(b.len());
        for j in lo..hi {
            if !bm[j] && a[i] == b[j] {
                am[i] = true;
                bm[j] = true;
                m += 1;
                break;
            }
        }
    }
    if m == 0 {
        return 0.0;
    }
    let (mut k, mut t) = (0usize, 0usize);
    for i in 0..a.len() {
        if am[i] {
            while !bm[k] {
                k += 1;
            }
            if a[i] != b[k] {
                t += 1;
            }
            k += 1;
        }
    }
    let m = m as f64;
    let jaro = (m / a.len() as f64 + m / b.len() as f64 + (m - t as f64 / 2.0) / m) / 3.0;
    let prefix = a.iter().zip(&b).take(4).take_while(|(x, y)| x == y).count() as f64;
    jaro + prefix * 0.1 * (1.0 - jaro)
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct TokenHit {
    pub query: String,
    pub candidate: Option<String>,
    pub similarity: f64,
    pub how: &'static str,
}

#[derive(Clone, Debug)]
pub struct Scored {
    pub score: f64,
    pub quality: &'static str,
    pub hits: Vec<TokenHit>,
}

#[derive(Clone, Debug)]
pub struct Name {
    pub toks: Vec<(String, Option<[u8; 4]>)>,
    pub flat: String,
}
impl Name {
    pub fn new(s: &str) -> Name {
        let toks = tokens(s);
        Name { flat: toks.join(" "), toks: toks.into_iter().map(|t| { let c = soundex(&t); (t, c) }).collect() }
    }
}

fn pair(q: &(String, Option<[u8; 4]>), c: &(String, Option<[u8; 4]>)) -> (f64, &'static str) {
    if q.0 == c.0 {
        return (1.0, "exact");
    }
    if q.0.len().abs_diff(c.0.len()) > 4 && !(q.0.len() >= 4 && c.0.starts_with(&q.0)) {
        return (0.0, "none");
    }
    if q.0.len() >= 4 && c.0.len() > q.0.len() && c.0.starts_with(&q.0) {
        return (0.9, "prefix");
    }
    let jw = jaro_winkler(&q.0, &c.0);
    let ph = matches!((q.1, c.1), (Some(a), Some(b)) if a == b);
    if jw >= 0.88 {
        (jw, "spelling")
    } else if ph && jw >= 0.7 {
        (0.82, "phonetic")
    } else {
        (0.0, "none")
    }
}

/// Score a query against one candidate name. Every query token is paired with its best unused candidate token.
pub fn score(q: &Name, c: &Name) -> Scored {
    if q.toks.is_empty() || c.toks.is_empty() {
        return Scored { score: 0.0, quality: "none", hits: vec![] };
    }
    if q.flat == c.flat {
        let hits = q.toks.iter().map(|t| TokenHit { query: t.0.clone(), candidate: Some(t.0.clone()), similarity: 1.0, how: "exact" }).collect();
        return Scored { score: 1.0, quality: "exact", hits };
    }
    let mut cands: Vec<(usize, usize, f64, &'static str)> = Vec::new();
    for (i, qt) in q.toks.iter().enumerate() {
        for (j, ct) in c.toks.iter().enumerate() {
            let (s, how) = pair(qt, ct);
            if s > 0.0 {
                cands.push((i, j, s, how));
            }
        }
    }
    cands.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    let (mut qu, mut cu) = (vec![None; q.toks.len()], vec![false; c.toks.len()]);
    for (i, j, s, how) in cands {
        if qu[i].is_none() && !cu[j] {
            qu[i] = Some((j, s, how));
            cu[j] = true;
        }
    }
    let qlen: f64 = q.toks.iter().map(|t| t.0.chars().count() as f64).sum();
    let clen: f64 = c.toks.iter().map(|t| t.0.chars().count() as f64).sum();
    let (mut qcov, mut ccov) = (0.0, 0.0);
    let mut hits = Vec::new();
    let mut quality = "exact-tokens";
    for (i, qt) in q.toks.iter().enumerate() {
        let l = qt.0.chars().count() as f64;
        match qu[i] {
            Some((j, s, how)) => {
                qcov += l * s;
                ccov += c.toks[j].0.chars().count() as f64;
                if how == "phonetic" {
                    quality = "phonetic";
                } else if s < 1.0 && quality != "phonetic" {
                    quality = "fuzzy";
                }
                hits.push(TokenHit { query: qt.0.clone(), candidate: Some(c.toks[j].0.clone()), similarity: (s * 100.0).round() / 100.0, how });
            }
            None => hits.push(TokenHit { query: qt.0.clone(), candidate: None, similarity: 0.0, how: "none" }),
        }
    }
    let sc = (qcov / qlen) * (0.6 + 0.4 * (ccov / clen));
    Scored { score: (sc * 1000.0).round() / 1000.0, quality, hits }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_and_strips_company_forms() {
        assert_eq!(normalise("Müller & Söhne, Ltd."), "muller   sohne  ltd ");
        assert_eq!(tokens("Rosneft Oil Company"), ["rosneft", "oil"]);
        assert_eq!(tokens("The Co"), ["the", "co"]);
        assert_eq!(tokens("Алабуга"), ["алабуга"]);
    }

    #[test]
    fn soundex_basics() {
        assert_eq!(soundex("robert"), soundex("rupert"));
        assert_eq!(soundex("robert"), Some(*b"R163"));
        assert!(soundex("ab").is_none());
        assert!(soundex("алабуга").is_none());
    }

    #[test]
    fn jaro_winkler_range() {
        assert_eq!(jaro_winkler("abc", "abc"), 1.0);
        assert!(jaro_winkler("martha", "marhta") > 0.96);
        assert!(jaro_winkler("abc", "xyz") < 0.1);
        assert_eq!(jaro_winkler("", "a"), 0.0);
    }

    #[test]
    fn scoring_is_explained() {
        let c = Name::new("Rosneft Oil Company");
        let exact = score(&Name::new("ROSNEFT OIL"), &c);
        assert_eq!(exact.score, 1.0);
        assert_eq!(exact.quality, "exact");
        let typo = score(&Name::new("rosnef oil"), &c);
        assert!(typo.score > 0.9 && typo.quality == "fuzzy", "{typo:?}");
        assert_eq!(typo.hits[0].how, "prefix");
        let phon = score(&Name::new("rosnift"), &Name::new("Rosneft"));
        assert!(phon.score >= 0.8, "{phon:?}");
        let partial = score(&Name::new("rosneft"), &c);
        assert!(partial.score < 1.0 && partial.score > 0.7);
        let miss = score(&Name::new("acme widgets"), &c);
        assert!(miss.score < 0.3);
        assert!(miss.hits.iter().all(|h| h.candidate.is_none()));
        assert_eq!(score(&Name::new(""), &c).score, 0.0);
    }

    #[test]
    fn tokens_are_not_reused() {
        let s = score(&Name::new("bank bank"), &Name::new("Bank Melli"));
        assert!(s.hits.iter().filter(|h| h.candidate.is_some()).count() == 1);
    }
}
