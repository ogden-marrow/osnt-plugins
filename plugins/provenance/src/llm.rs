//! LLM wire formats. The agent loop speaks the OpenAI chat shape internally (messages with `tool_calls` and `tool`
//! results); this module translates that to and from the providers whose native APIs differ:
//! Anthropic (Messages API) and Google Gemini (generateContent). OpenAI-compatible servers pass through unchanged.

use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Style {
    #[default]
    OpenAi,
    Anthropic,
    Gemini,
}

impl Style {
    pub fn parse(s: &str) -> Style {
        match s.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Style::Anthropic,
            "gemini" | "google" => Style::Gemini,
            _ => Style::OpenAi,
        }
    }
}

pub struct Request {
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Value,
}

fn text_of(m: &Value) -> String {
    m["content"].as_str().unwrap_or("").to_string()
}

fn parse_args(call: &Value) -> Value {
    call["function"]["arguments"].as_str().and_then(|s| serde_json::from_str(s).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// Append a message, merging into the previous one when the role repeats (both APIs want strict alternation).
fn push(out: &mut Vec<Value>, role: &str, key: &str, parts: Vec<Value>) {
    if let Some(last) = out.last_mut().filter(|l| l["role"] == role) {
        last[key].as_array_mut().unwrap().extend(parts);
    } else {
        out.push(json!({ "role": role, key: parts }));
    }
}

fn encode(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Gemini accepts only an OpenAPI subset of JSON Schema.
fn gemini_schema(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.iter().filter(|(k, _)| !matches!(k.as_str(), "additionalProperties" | "$schema" | "default")).map(|(k, v)| (k.clone(), gemini_schema(v))).collect::<Map<_, _>>()),
        Value::Array(a) => Value::Array(a.iter().map(gemini_schema).collect()),
        other => other.clone(),
    }
}

pub fn build(style: Style, base: &str, model: &str, key: &str, messages: &[Value], tools: Option<&[Value]>, json_mode: bool) -> Request {
    let base = base.trim_end_matches('/');
    match style {
        Style::OpenAi => {
            let mut body = json!({ "model": model, "messages": messages, "temperature": 0.2, "max_tokens": 2500 });
            if let Some(t) = tools {
                body["tools"] = json!(t);
                body["tool_choice"] = json!("auto");
            }
            if json_mode {
                body["response_format"] = json!({ "type": "json_object" });
            }
            let headers = if key.is_empty() { vec![] } else { vec![("Authorization", format!("Bearer {key}"))] };
            Request { url: format!("{base}/chat/completions"), headers, body }
        }
        Style::Anthropic => {
            let mut system = vec![];
            let mut out: Vec<Value> = vec![];
            let mut used: Vec<String> = vec![];
            for m in messages {
                match m["role"].as_str().unwrap_or("") {
                    "system" => system.push(text_of(m)),
                    "assistant" => {
                        let mut blocks = vec![];
                        if !text_of(m).is_empty() {
                            blocks.push(json!({ "type": "text", "text": text_of(m) }));
                        }
                        for c in m["tool_calls"].as_array().into_iter().flatten() {
                            let name = c["function"]["name"].as_str().unwrap_or("").to_string();
                            blocks.push(json!({ "type": "tool_use", "id": c["id"], "name": name, "input": parse_args(c) }));
                            if !used.contains(&name) {
                                used.push(name);
                            }
                        }
                        if blocks.is_empty() {
                            blocks.push(json!({ "type": "text", "text": "(no content)" }));
                        }
                        push(&mut out, "assistant", "content", blocks);
                    }
                    "tool" => push(&mut out, "user", "content", vec![json!({ "type": "tool_result", "tool_use_id": m["tool_call_id"], "content": text_of(m) })]),
                    _ => push(&mut out, "user", "content", vec![json!({ "type": "text", "text": text_of(m) })]),
                }
            }
            let mut body = json!({ "model": model, "messages": out, "temperature": 0.2, "max_tokens": 2500 });
            if !system.is_empty() {
                body["system"] = json!(system.join("\n\n"));
            }
            match tools {
                Some(t) => {
                    body["tools"] = json!(t.iter().map(|d| json!({ "name": d["function"]["name"], "description": d["function"]["description"], "input_schema": d["function"]["parameters"] })).collect::<Vec<_>>());
                    body["tool_choice"] = json!({ "type": "auto" });
                }
                // The history already holds tool calls, and Anthropic insists the tools are declared; forbid more calls.
                None if !used.is_empty() => {
                    body["tools"] = json!(used.iter().map(|n| json!({ "name": n, "description": "", "input_schema": { "type": "object" } })).collect::<Vec<_>>());
                    body["tool_choice"] = json!({ "type": "none" });
                }
                None => {}
            }
            let mut headers = vec![("anthropic-version", "2023-06-01".to_string())];
            if !key.is_empty() {
                headers.push(("x-api-key", key.to_string()));
            }
            Request { url: format!("{base}/messages"), headers, body }
        }
        Style::Gemini => {
            let mut system = vec![];
            let mut out: Vec<Value> = vec![];
            let mut names: Vec<(String, String)> = vec![]; // tool call id -> function name
            for m in messages {
                match m["role"].as_str().unwrap_or("") {
                    "system" => system.push(text_of(m)),
                    "assistant" => {
                        let mut parts = vec![];
                        if !text_of(m).is_empty() {
                            parts.push(json!({ "text": text_of(m) }));
                        }
                        for c in m["tool_calls"].as_array().into_iter().flatten() {
                            let name = c["function"]["name"].as_str().unwrap_or("").to_string();
                            names.push((c["id"].as_str().unwrap_or("").to_string(), name.clone()));
                            let mut p = json!({ "functionCall": { "name": name, "args": parse_args(c) } });
                            if let Some(sig) = c["thought_signature"].as_str() {
                                p["thoughtSignature"] = json!(sig);
                            }
                            parts.push(p);
                        }
                        if parts.is_empty() {
                            parts.push(json!({ "text": "(no content)" }));
                        }
                        push(&mut out, "model", "parts", parts);
                    }
                    "tool" => {
                        let id = m["tool_call_id"].as_str().unwrap_or("");
                        let name = names.iter().find(|(i, _)| i == id).map(|(_, n)| n.clone()).unwrap_or_default();
                        push(&mut out, "user", "parts", vec![json!({ "functionResponse": { "name": name, "response": { "result": text_of(m) } } })]);
                    }
                    _ => push(&mut out, "user", "parts", vec![json!({ "text": text_of(m) })]),
                }
            }
            let mut gen_cfg = json!({ "temperature": 0.2, "maxOutputTokens": 2500 });
            if json_mode {
                gen_cfg["responseMimeType"] = json!("application/json");
            }
            let mut body = json!({ "contents": out, "generationConfig": gen_cfg });
            if !system.is_empty() {
                body["systemInstruction"] = json!({ "parts": [{ "text": system.join("\n\n") }] });
            }
            if let Some(t) = tools {
                let decls: Vec<Value> = t
                    .iter()
                    .map(|d| {
                        let f = &d["function"];
                        let mut decl = json!({ "name": f["name"], "description": f["description"] });
                        // Gemini rejects an object schema with no properties: no-argument tools omit it.
                        if f["parameters"]["properties"].as_object().is_some_and(|p| !p.is_empty()) {
                            decl["parameters"] = gemini_schema(&f["parameters"]);
                        }
                        decl
                    })
                    .collect();
                body["tools"] = json!([{ "functionDeclarations": decls }]);
            }
            let headers = if key.is_empty() { vec![] } else { vec![("x-goog-api-key", key.to_string())] };
            Request { url: format!("{base}/models/{}:generateContent", encode(model)), headers, body }
        }
    }
}

/// The provider's reply as an OpenAI-style assistant message (`content`, optional `tool_calls`), or None if it has none.
pub fn parse(style: Style, reply: &Value) -> Option<Value> {
    match style {
        Style::OpenAi => Some(reply["choices"][0]["message"].clone()).filter(|m| !m.is_null()),
        Style::Anthropic => {
            let blocks = reply["content"].as_array()?;
            let text: String = blocks.iter().filter(|b| b["type"] == "text").filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("");
            let calls: Vec<Value> = blocks
                .iter()
                .filter(|b| b["type"] == "tool_use")
                .map(|b| json!({ "id": b["id"], "type": "function", "function": { "name": b["name"], "arguments": b["input"].to_string() } }))
                .collect();
            Some(message(text, calls))
        }
        Style::Gemini => {
            let parts = reply["candidates"][0]["content"]["parts"].as_array()?;
            let text: String = parts.iter().filter(|p| p["thought"] != true).filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join("");
            let calls: Vec<Value> = parts
                .iter()
                .filter(|p| p["functionCall"].is_object())
                .enumerate()
                .map(|(i, p)| {
                    let mut c = json!({ "id": format!("call_{i}"), "type": "function", "function": { "name": p["functionCall"]["name"], "arguments": p["functionCall"]["args"].to_string() } });
                    if let Some(sig) = p["thoughtSignature"].as_str() {
                        c["thought_signature"] = json!(sig);
                    }
                    c
                })
                .collect();
            Some(message(text, calls))
        }
    }
}

fn message(text: String, calls: Vec<Value>) -> Value {
    let mut m = json!({ "role": "assistant", "content": if text.is_empty() { Value::Null } else { json!(text) } });
    if !calls.is_empty() {
        m["tool_calls"] = json!(calls);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defs() -> Vec<Value> {
        vec![
            json!({ "type": "function", "function": { "name": "analyze", "description": "d", "parameters": { "type": "object", "properties": {}, "required": [] } } }),
            json!({ "type": "function", "function": { "name": "lens", "description": "l", "parameters": { "type": "object", "properties": { "image_url": { "type": "string" } }, "additionalProperties": false } } }),
        ]
    }

    fn history() -> Vec<Value> {
        vec![
            json!({ "role": "system", "content": "sys" }),
            json!({ "role": "user", "content": "go" }),
            json!({ "role": "assistant", "content": null, "tool_calls": [
                { "id": "c1", "type": "function", "function": { "name": "analyze", "arguments": "{}" }, "thought_signature": "SIG" },
                { "id": "c2", "type": "function", "function": { "name": "lens", "arguments": "{\"image_url\":\"http://x\"}" } } ] }),
            json!({ "role": "tool", "tool_call_id": "c1", "content": "r1" }),
            json!({ "role": "tool", "tool_call_id": "c2", "content": "r2" }),
            json!({ "role": "user", "content": "No more tool calls" }),
        ]
    }

    #[test]
    fn openai_passthrough_and_keyless() {
        let r = build(Style::OpenAi, "http://h/v1/", "m", "", &history(), Some(&defs()), false);
        assert_eq!(r.url, "http://h/v1/chat/completions");
        assert!(r.headers.is_empty());
        let r = build(Style::OpenAi, "http://h", "m", "k", &history(), None, true);
        assert_eq!(r.headers[0].1, "Bearer k");
        assert_eq!(r.body["response_format"]["type"], "json_object");
    }

    #[test]
    fn anthropic_request_shape() {
        let r = build(Style::Anthropic, "https://api.anthropic.com/v1", "claude-x", "k", &history(), Some(&defs()), false);
        assert_eq!(r.url, "https://api.anthropic.com/v1/messages");
        assert!(r.headers.iter().any(|(h, v)| *h == "x-api-key" && v == "k"));
        assert_eq!(r.body["system"], "sys");
        let m = r.body["messages"].as_array().unwrap();
        assert_eq!(m.len(), 3, "user, assistant(tool_use), user(tool_results + text)");
        assert_eq!(m[1]["content"][1]["input"]["image_url"], "http://x");
        let last = m[2]["content"].as_array().unwrap();
        assert_eq!(last.len(), 3);
        assert_eq!(last[0]["type"], "tool_result");
        assert_eq!(last[0]["tool_use_id"], "c1");
        assert_eq!(last[2]["type"], "text");
        assert_eq!(r.body["tools"][1]["input_schema"]["properties"]["image_url"]["type"], "string");
    }

    #[test]
    fn anthropic_final_turn_still_declares_tools_but_forbids_them() {
        let r = build(Style::Anthropic, "http://h", "m", "k", &history(), None, false);
        assert_eq!(r.body["tool_choice"]["type"], "none");
        assert_eq!(r.body["tools"].as_array().unwrap().len(), 2);
        let r = build(Style::Anthropic, "http://h", "m", "k", &history()[..2], None, false);
        assert!(r.body.get("tools").is_none());
    }

    #[test]
    fn gemini_request_shape() {
        let r = build(Style::Gemini, "https://generativelanguage.googleapis.com/v1beta", "gemini-2.5-flash", "k", &history(), Some(&defs()), true);
        assert_eq!(r.url, "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent");
        assert_eq!(r.body["systemInstruction"]["parts"][0]["text"], "sys");
        assert_eq!(r.body["generationConfig"]["responseMimeType"], "application/json");
        let c = r.body["contents"].as_array().unwrap();
        assert_eq!(c.len(), 3);
        assert_eq!(c[1]["role"], "model");
        assert_eq!(c[1]["parts"][0]["thoughtSignature"], "SIG");
        assert_eq!(c[2]["parts"][0]["functionResponse"]["name"], "analyze");
        assert_eq!(c[2]["parts"][1]["functionResponse"]["name"], "lens");
        let d = r.body["tools"][0]["functionDeclarations"].as_array().unwrap();
        assert!(d[0].get("parameters").is_none(), "empty-properties schema is omitted");
        assert!(d[1]["parameters"].get("additionalProperties").is_none());
    }

    #[test]
    fn parses_native_replies() {
        let a = parse(Style::Anthropic, &json!({ "content": [{ "type": "text", "text": "hi " }, { "type": "tool_use", "id": "t1", "name": "lens", "input": { "image_url": "u" } }] })).unwrap();
        assert_eq!(a["content"], "hi ");
        assert_eq!(a["tool_calls"][0]["function"]["name"], "lens");
        assert_eq!(serde_json::from_str::<Value>(a["tool_calls"][0]["function"]["arguments"].as_str().unwrap()).unwrap()["image_url"], "u");

        let g = parse(Style::Gemini, &json!({ "candidates": [{ "content": { "parts": [{ "thought": true, "text": "hmm" }, { "functionCall": { "name": "analyze", "args": {} }, "thoughtSignature": "S" }] } }] })).unwrap();
        assert!(g["content"].is_null());
        assert_eq!(g["tool_calls"][0]["id"], "call_0");
        assert_eq!(g["tool_calls"][0]["thought_signature"], "S");
        assert!(parse(Style::Gemini, &json!({ "promptFeedback": { "blockReason": "SAFETY" } })).is_none());
        assert_eq!(parse(Style::OpenAi, &json!({ "choices": [{ "message": { "content": "x" } }] })).unwrap()["content"], "x");
    }

    #[test]
    fn style_names() {
        assert_eq!(Style::parse(" Claude "), Style::Anthropic);
        assert_eq!(Style::parse("gemini"), Style::Gemini);
        assert_eq!(Style::parse(""), Style::OpenAi);
    }
}
