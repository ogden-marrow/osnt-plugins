//! A small, hand-written technology signature set (our own rules; not copied from Wappalyzer or similar).
//! Each signature fires on response headers, cookie names, meta tags, script/link URLs or markup fragments.

use serde_json::{Value, json};

use crate::{headers::Headers, html::{Tag, meta}};

enum R {
    /// Header present (needle empty) or containing the needle (case-insensitive).
    Header(&'static str, &'static str),
    CookiePrefix(&'static str),
    Meta(&'static str, &'static str),
    Script(&'static str),
    Link(&'static str),
    Html(&'static str),
}

struct Sig {
    name: &'static str,
    cat: &'static str,
    rules: &'static [R],
}

use R::*;
static SIGS: &[Sig] = &[
    Sig { name: "nginx", cat: "Web server", rules: &[Header("server", "nginx")] },
    Sig { name: "Apache HTTP Server", cat: "Web server", rules: &[Header("server", "apache")] },
    Sig { name: "Microsoft IIS", cat: "Web server", rules: &[Header("server", "microsoft-iis")] },
    Sig { name: "LiteSpeed", cat: "Web server", rules: &[Header("server", "litespeed")] },
    Sig { name: "Caddy", cat: "Web server", rules: &[Header("server", "caddy")] },
    Sig { name: "Envoy", cat: "Web server", rules: &[Header("server", "envoy")] },
    Sig { name: "Cloudflare", cat: "CDN / edge", rules: &[Header("cf-ray", ""), Header("server", "cloudflare")] },
    Sig { name: "Amazon CloudFront", cat: "CDN / edge", rules: &[Header("x-amz-cf-id", ""), Header("via", "cloudfront")] },
    Sig { name: "Fastly", cat: "CDN / edge", rules: &[Header("x-served-by", "cache-"), Header("fastly-debug-digest", "")] },
    Sig { name: "Akamai", cat: "CDN / edge", rules: &[Header("x-akamai-transformed", ""), Header("server", "akamaighost")] },
    Sig { name: "Vercel", cat: "Hosting", rules: &[Header("x-vercel-id", ""), Header("server", "vercel")] },
    Sig { name: "Netlify", cat: "Hosting", rules: &[Header("x-nf-request-id", ""), Header("server", "netlify")] },
    Sig { name: "GitHub-served", cat: "Hosting", rules: &[Header("x-github-request-id", "")] },
    Sig { name: "Google Cloud / Firebase Hosting", cat: "Hosting", rules: &[Header("x-firebase-appcheck", ""), Header("server", "gse"), Header("via", "google")] },
    Sig { name: "Heroku", cat: "Hosting", rules: &[Header("via", "vegur")] },
    Sig { name: "PHP", cat: "Language", rules: &[Header("x-powered-by", "php"), CookiePrefix("PHPSESSID")] },
    Sig { name: "ASP.NET", cat: "Framework", rules: &[Header("x-aspnet-version", ""), Header("x-powered-by", "asp.net"), CookiePrefix("ASP.NET_SessionId")] },
    Sig { name: "Express", cat: "Framework", rules: &[Header("x-powered-by", "express"), CookiePrefix("connect.sid")] },
    Sig { name: "Java servlet container", cat: "Framework", rules: &[CookiePrefix("JSESSIONID"), Header("x-powered-by", "servlet")] },
    Sig { name: "Laravel", cat: "Framework", rules: &[CookiePrefix("laravel_session"), CookiePrefix("XSRF-TOKEN")] },
    Sig { name: "Django", cat: "Framework", rules: &[CookiePrefix("csrftoken")] },
    Sig { name: "Ruby on Rails", cat: "Framework", rules: &[CookiePrefix("_rails"), Meta("csrf-param", "authenticity_token"), Header("x-runtime", "")] },
    Sig { name: "WordPress", cat: "CMS", rules: &[Meta("generator", "wordpress"), Html("/wp-content/"), Html("/wp-includes/"), Link("api.w.org")] },
    Sig { name: "Drupal", cat: "CMS", rules: &[Meta("generator", "drupal"), Header("x-drupal-cache", ""), Header("x-generator", "drupal"), Html("/sites/default/files/")] },
    Sig { name: "Joomla", cat: "CMS", rules: &[Meta("generator", "joomla"), Html("/media/jui/")] },
    Sig { name: "Ghost", cat: "CMS", rules: &[Meta("generator", "ghost")] },
    Sig { name: "Hugo", cat: "Static site generator", rules: &[Meta("generator", "hugo")] },
    Sig { name: "Jekyll", cat: "Static site generator", rules: &[Meta("generator", "jekyll")] },
    Sig { name: "Docusaurus", cat: "Static site generator", rules: &[Meta("generator", "docusaurus")] },
    Sig { name: "Wix", cat: "Site builder", rules: &[Meta("generator", "wix.com"), Header("x-wix-request-id", "")] },
    Sig { name: "Squarespace", cat: "Site builder", rules: &[Meta("generator", "squarespace"), Header("server", "squarespace")] },
    Sig { name: "Webflow", cat: "Site builder", rules: &[Html("data-wf-site"), Meta("generator", "webflow")] },
    Sig { name: "Shopify", cat: "E-commerce", rules: &[Header("x-shopid", ""), Script("cdn.shopify.com"), Html("shopify.theme")] },
    Sig { name: "WooCommerce", cat: "E-commerce", rules: &[Html("woocommerce"), Meta("generator", "woocommerce")] },
    Sig { name: "Magento", cat: "E-commerce", rules: &[CookiePrefix("mage-"), Html("/static/frontend/magento")] },
    Sig { name: "Next.js", cat: "JavaScript framework", rules: &[Header("x-powered-by", "next.js"), Html("/_next/static/"), Html("__next_data__")] },
    Sig { name: "Nuxt", cat: "JavaScript framework", rules: &[Html("/_nuxt/"), Html("__nuxt")] },
    Sig { name: "Gatsby", cat: "JavaScript framework", rules: &[Meta("generator", "gatsby"), Html("___gatsby")] },
    Sig { name: "React", cat: "JavaScript framework", rules: &[Html("data-reactroot"), Html("react-dom"), Script("react.production.min")] },
    Sig { name: "Vue.js", cat: "JavaScript framework", rules: &[Html("data-v-app"), Script("vue.min.js"), Script("vue.global"), Html("__vue__")] },
    Sig { name: "Angular", cat: "JavaScript framework", rules: &[Html("ng-version="), Html("<app-root")] },
    Sig { name: "Svelte / SvelteKit", cat: "JavaScript framework", rules: &[Html("/_app/immutable/"), Html("data-sveltekit")] },
    Sig { name: "jQuery", cat: "JavaScript library", rules: &[Script("jquery")] },
    Sig { name: "Bootstrap", cat: "UI framework", rules: &[Link("bootstrap"), Script("bootstrap")] },
    Sig { name: "Tailwind CSS", cat: "UI framework", rules: &[Link("tailwind"), Html("tailwindcss")] },
    Sig { name: "Font Awesome", cat: "UI framework", rules: &[Link("font-awesome"), Link("fontawesome")] },
    Sig { name: "Google Analytics / Tag Manager", cat: "Analytics", rules: &[Script("googletagmanager.com"), Script("google-analytics.com"), Html("gtag(")] },
    Sig { name: "Matomo", cat: "Analytics", rules: &[Script("matomo"), Script("piwik")] },
    Sig { name: "Plausible", cat: "Analytics", rules: &[Script("plausible.io")] },
    Sig { name: "Cloudflare Web Analytics", cat: "Analytics", rules: &[Script("static.cloudflareinsights.com")] },
    Sig { name: "Hotjar", cat: "Analytics", rules: &[Script("hotjar.com")] },
    Sig { name: "Meta Pixel", cat: "Advertising", rules: &[Script("connect.facebook.net"), Html("fbq(")] },
    Sig { name: "reCAPTCHA", cat: "Security", rules: &[Script("google.com/recaptcha"), Script("gstatic.com/recaptcha")] },
    Sig { name: "hCaptcha", cat: "Security", rules: &[Script("hcaptcha.com")] },
    Sig { name: "Cloudflare Turnstile", cat: "Security", rules: &[Script("challenges.cloudflare.com")] },
    Sig { name: "Stripe", cat: "Payments", rules: &[Script("js.stripe.com")] },
    Sig { name: "PayPal", cat: "Payments", rules: &[Script("paypal.com/sdk")] },
    Sig { name: "Google Fonts", cat: "Fonts", rules: &[Link("fonts.googleapis.com")] },
    Sig { name: "Intercom", cat: "Chat", rules: &[Script("intercom")] },
    Sig { name: "Sentry", cat: "Monitoring", rules: &[Script("sentry"), Header("report-to", "sentry")] },
];

/// Pull a version number that follows the product name, as in "nginx/1.18.0" or "WordPress 6.4.2".
pub fn version_after(value: &str, product: &str) -> Option<String> {
    let l = value.to_ascii_lowercase();
    let p = l.find(&product.to_ascii_lowercase())? + product.len();
    let rest = value.get(p..)?.trim_start_matches(['/', ' ', '-', '_', ':']);
    let v: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    (v.chars().next().is_some_and(|c| c.is_ascii_digit())).then(|| v.trim_end_matches('.').to_string())
}

pub fn detect(h: &Headers, cookies: &[String], tags: &[Tag], html_lower: &str) -> Vec<Value> {
    let scripts: Vec<String> = tags.iter().filter(|t| t.name == "script").filter_map(|t| t.attr("src")).map(str::to_ascii_lowercase).collect();
    let links: Vec<String> = tags.iter().filter(|t| t.name == "link").filter_map(|t| t.attr("href").or(t.attr("rel"))).map(str::to_ascii_lowercase).collect();
    let mut out = vec![];
    for sig in SIGS {
        let mut ev: Vec<String> = vec![];
        let mut version = None;
        for r in sig.rules {
            match r {
                Header(k, needle) => {
                    if let Some(v) = crate::headers::get(h, k) {
                        if needle.is_empty() || v.to_ascii_lowercase().contains(needle) {
                            ev.push(format!("header {k}{}", if needle.is_empty() { String::new() } else { format!(": {}", v.chars().take(60).collect::<String>()) }));
                            version = version.or_else(|| version_after(v, sig.name.split(' ').next().unwrap_or(sig.name)));
                        }
                    }
                }
                CookiePrefix(p) => {
                    if let Some(c) = cookies.iter().find(|c| c.to_ascii_lowercase().starts_with(&p.to_ascii_lowercase())) {
                        ev.push(format!("cookie {c}"));
                    }
                }
                Meta(k, needle) => {
                    if let Some(v) = meta(tags, k) {
                        if v.to_ascii_lowercase().contains(needle) {
                            ev.push(format!("meta {k}: {}", v.chars().take(60).collect::<String>()));
                            version = version.or_else(|| version_after(v, sig.name));
                        }
                    }
                }
                Script(n) => {
                    if let Some(s) = scripts.iter().find(|s| s.contains(n)) {
                        ev.push(format!("script {}", s.chars().take(70).collect::<String>()));
                        version = version.or_else(|| {
                            s.match_indices(n).find_map(|(i, _)| {
                                let after = s[i + n.len()..].trim_start_matches(['-', '/', '@', '.', '_', 'v']);
                                let v: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                                (v.contains('.') && v.chars().next().is_some_and(|c| c.is_ascii_digit())).then(|| v.trim_end_matches('.').to_string())
                            })
                        });
                    }
                }
                Link(n) => {
                    if let Some(s) = links.iter().find(|s| s.contains(n)) {
                        ev.push(format!("link {}", s.chars().take(70).collect::<String>()));
                    }
                }
                Html(n) => {
                    if html_lower.contains(n) {
                        ev.push(format!("markup contains {n}"));
                    }
                }
            }
        }
        if !ev.is_empty() {
            ev.truncate(3);
            out.push(json!({ "name": sig.name, "category": sig.cat, "version": version, "evidence": ev }));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::html::scan;

    fn hd(v: &[(&str, &str)]) -> Headers {
        v.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }
    fn names(v: &[Value]) -> Vec<String> {
        v.iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn versions() {
        assert_eq!(version_after("nginx/1.18.0 (Ubuntu)", "nginx").as_deref(), Some("1.18.0"));
        assert_eq!(version_after("WordPress 6.4.2", "WordPress").as_deref(), Some("6.4.2"));
        assert_eq!(version_after("nginx", "nginx"), None);
        assert_eq!(version_after("Apache/2.4.", "apache").as_deref(), Some("2.4"));
    }

    #[test]
    fn detects_from_each_kind_of_evidence() {
        let html = r#"<html><head><meta name="generator" content="WordPress 6.4.2"><link rel="stylesheet" href="/wp-content/themes/x/style.css"><script src="https://code.jquery.com/jquery-3.7.1.min.js"></script><script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script></head><body><div id="__next"></div></body></html>"#;
        let tags = scan(html);
        let t = detect(&hd(&[("server", "nginx/1.18.0"), ("cf-ray", "abc"), ("x-powered-by", "PHP/8.1.2")]), &["PHPSESSID".into(), "wordpress_logged_in_x".into()], &tags, &html.to_ascii_lowercase());
        let n = names(&t);
        for want in ["nginx", "Cloudflare", "PHP", "WordPress", "jQuery", "Google Analytics / Tag Manager"] {
            assert!(n.contains(&want.to_string()), "missing {want}: {n:?}");
        }
        let wp = t.iter().find(|x| x["name"] == "WordPress").unwrap();
        assert_eq!(wp["version"], "6.4.2");
        assert_eq!(t.iter().find(|x| x["name"] == "nginx").unwrap()["version"], "1.18.0");
        assert_eq!(t.iter().find(|x| x["name"] == "PHP").unwrap()["version"], "8.1.2");
        assert_eq!(t.iter().find(|x| x["name"] == "jQuery").unwrap()["version"], "3.7.1");
        assert!(!n.contains(&"Drupal".to_string()) && !n.contains(&"Shopify".to_string()));
    }

    #[test]
    fn empty_page_has_no_tech() {
        assert!(detect(&hd(&[]), &[], &[], "").is_empty());
    }
}
