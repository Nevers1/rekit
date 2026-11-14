//! What a page actually does: the DOM after scripts, the requests it made,
//! the console, the cookies, a screenshot.
//!
//! Every other web tool in this crate works on text at rest. That answers
//! "which endpoints are named in this bundle", not "which one is called on
//! load, with what, and what came back". A real browser answers the second
//! question, and that is where an access-control bug usually shows itself.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::cdp::Chrome;

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const TEXT_LIMIT: usize = 200_000;
const ROW_LIMIT: usize = 300;

/// How long to keep reading protocol events before printing a table.
///
/// A response and its `loadingFinished` can land a few milliseconds after the
/// command that triggered them, and `requests` would then show a request with
/// no status. Half a second of quiet is enough for a normal page and short
/// enough that the tool still feels immediate.
const NETWORK_SETTLE: Duration = Duration::from_millis(600);

#[derive(Debug, Clone)]
pub struct Request {
    pub url: String,
    /// dom | text | html | title | eval | screenshot | pdf | cookies |
    /// set-cookie | requests | console | links | storage | click | fill |
    /// wait | snapshot
    pub action: String,
    pub js: Option<String>,
    /// CSS selector, for the actions that take one.
    pub selector: Option<String>,
    /// Value for `fill`.
    pub value: Option<String>,
    /// Wait for this CSS selector after loading.
    pub wait: Option<String>,
    pub width: u32,
    pub height: u32,
    pub full_page: bool,
    /// Where to write a screenshot or pdf; a cache path when omitted.
    pub output: Option<String>,
    pub timeout_ms: u64,
    /// Extra headers for every request the page makes.
    pub headers: Vec<String>,
    /// Cookies to set before loading, `name=value; domain=…; path=…`.
    pub cookies: Vec<String>,
    pub user_agent: Option<String>,
    /// Attach to a running browser instead of starting one.
    pub cdp_url: Option<String>,
    pub headless: bool,
    /// Keep the throwaway profile (cookies, cache) for inspection.
    pub keep_profile: bool,
    pub ignore_cert: bool,
    pub json: bool,
}

impl Default for Request {
    fn default() -> Self {
        Request {
            url: String::new(),
            action: "text".to_string(),
            js: None,
            selector: None,
            value: None,
            wait: None,
            width: 1366,
            height: 900,
            full_page: false,
            output: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            headers: Vec::new(),
            cookies: Vec::new(),
            user_agent: None,
            cdp_url: None,
            headless: true,
            keep_profile: false,
            ignore_cert: false,
            json: false,
        }
    }
}

const ACTIONS: &[&str] = &[
    "dom",
    "text",
    "html",
    "title",
    "eval",
    "screenshot",
    "pdf",
    "cookies",
    "set-cookie",
    "requests",
    "console",
    "links",
    "storage",
    "click",
    "fill",
    "wait",
    "snapshot",
];

pub fn run(req: &Request) -> Result<String> {
    let action = req.action.trim().to_ascii_lowercase();
    let action = if action.is_empty() {
        "text".to_string()
    } else {
        action
    };
    if !ACTIONS.contains(&action.as_str()) {
        bail!("unknown action {action:?}: use {}", ACTIONS.join(", "));
    }
    if req.url.trim().is_empty() {
        bail!("pass url: a page has to be loaded before it can be inspected");
    }
    check_scheme(&req.url)?;
    if action == "eval" && req.js.as_deref().unwrap_or("").trim().is_empty() {
        bail!("action eval needs js: the expression to run in the page");
    }
    if matches!(action.as_str(), "click" | "fill" | "wait")
        && req.selector.as_deref().unwrap_or("").trim().is_empty()
    {
        bail!("action {action} needs selector: a CSS selector");
    }
    if action == "fill" && req.value.is_none() {
        bail!("action fill needs value: the text to put in the field");
    }

    let timeout = Duration::from_millis(req.timeout_ms.max(1_000));
    let mut chrome = match &req.cdp_url {
        Some(url) => Chrome::attach(url)?,
        None => Chrome::launch(req.headless, (req.width, req.height), req.keep_profile)?,
    };
    chrome.set_timeout(timeout);
    chrome.enable_domains()?;
    if (req.width, req.height) != (0, 0) {
        chrome.set_viewport(req.width, req.height)?;
    }
    if let Some(agent) = &req.user_agent {
        chrome.set_user_agent(agent)?;
    }
    if req.ignore_cert {
        chrome.ignore_certificate_errors()?;
    }
    if !req.headers.is_empty() {
        let parsed = parse_headers(&req.headers)?;
        chrome.set_headers(&parsed)?;
    }
    for spec in &req.cookies {
        chrome.set_cookie(spec)?;
    }

    if !req.url.trim().is_empty() && req.url != "about:blank" {
        chrome.navigate(&req.url, timeout)?;
    }
    if let Some(selector) = &req.wait {
        wait_for(&mut chrome, selector, timeout)?;
    }

    let value = match action.as_str() {
        "dom" | "html" => {
            let js = match &req.selector {
                Some(selector) => format!(
                    "document.querySelector({})?.outerHTML ?? null",
                    js_string(selector)
                ),
                None => "document.documentElement.outerHTML".to_string(),
            };
            let html = chrome.evaluate(&js)?;
            match html.as_str() {
                Some(text) => json!({"html": text}),
                None => bail!(
                    "selector {:?} matched nothing",
                    req.selector.clone().unwrap_or_default()
                ),
            }
        }
        "text" => {
            let js = match &req.selector {
                Some(selector) => format!(
                    "document.querySelector({})?.innerText ?? null",
                    js_string(selector)
                ),
                None => "document.body ? document.body.innerText : ''".to_string(),
            };
            let text = chrome.evaluate(&js)?;
            match text.as_str() {
                Some(text) => json!({"text": cap(text, TEXT_LIMIT)}),
                None => bail!(
                    "selector {:?} matched nothing",
                    req.selector.clone().unwrap_or_default()
                ),
            }
        }
        "title" => json!({
            "url": chrome.evaluate("location.href")?,
            "title": chrome.evaluate("document.title")?,
        }),
        "eval" => {
            let expression = req.js.as_deref().unwrap_or_default();
            let result = chrome.evaluate(expression)?;
            json!({"result": result})
        }
        "screenshot" => {
            let bytes = chrome.screenshot(req.full_page)?;
            let path = write_output(&req.output, "png", &bytes)?;
            json!({"path": path.display().to_string(), "bytes": bytes.len()})
        }
        "pdf" => {
            let bytes = chrome.pdf()?;
            let path = write_output(&req.output, "pdf", &bytes)?;
            json!({"path": path.display().to_string(), "bytes": bytes.len()})
        }
        "cookies" => {
            let cookies = chrome.cookies()?;
            json!({"cookies": render_cookies(&cookies)})
        }
        "set-cookie" => {
            if req.cookies.is_empty() {
                bail!("action set-cookie needs cookies: one `name=value; domain=…` per entry");
            }
            json!({"cookies": render_cookies(&chrome.cookies()?)})
        }
        "requests" => {
            chrome.pump(NETWORK_SETTLE);
            json!({"requests": request_rows(&chrome)})
        }
        "console" => {
            chrome.pump(NETWORK_SETTLE);
            json!({"console": console_rows(&chrome)})
        }
        "links" => {
            let links = chrome.evaluate(
                "JSON.stringify([...document.querySelectorAll('a[href]')]\
                 .map(a => ({href: a.href, text: (a.innerText || '').trim().slice(0, 120)})))",
            )?;
            let parsed: Value = match links.as_str() {
                Some(text) => serde_json::from_str(text).unwrap_or(json!([])),
                None => links.clone(),
            };
            json!({"links": parsed})
        }
        "storage" => {
            let data = chrome.evaluate(
                "JSON.stringify({localStorage: Object.fromEntries(Object.entries(localStorage)),\
                 sessionStorage: Object.fromEntries(Object.entries(sessionStorage))})",
            )?;
            let parsed: Value = match data.as_str() {
                Some(text) => serde_json::from_str(text).unwrap_or(json!({})),
                None => data.clone(),
            };
            json!({"storage": parsed})
        }
        "click" => {
            let selector = req.selector.as_deref().unwrap_or_default();
            let js = format!(
                "(() => {{ const el = document.querySelector({sel}); if (!el) return false; \
                 el.click(); return true; }})()",
                sel = js_string(selector)
            );
            let hit = chrome.evaluate(&js)?.as_bool().unwrap_or(false);
            if !hit {
                bail!("selector {selector:?} matched nothing");
            }
            // Give the click's handler a moment so a follow-up read shows the
            // result rather than the state before it.
            std::thread::sleep(Duration::from_millis(300));
            json!({
                "clicked": selector,
                "url": chrome.evaluate("location.href")?,
                "result": after_action(&mut chrome, req)?,
            })
        }
        "fill" => {
            let selector = req.selector.as_deref().unwrap_or_default();
            let value = req.value.clone().unwrap_or_default();
            let js = format!(
                "(() => {{ const el = document.querySelector({sel}); if (!el) return false; \
                 const proto = el instanceof HTMLTextAreaElement \
                   ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; \
                 Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, {val}); \
                 el.dispatchEvent(new Event('input', {{bubbles: true}})); \
                 el.dispatchEvent(new Event('change', {{bubbles: true}})); \
                 return true; }})()",
                sel = js_string(selector),
                val = js_string(&value)
            );
            let hit = chrome.evaluate(&js)?.as_bool().unwrap_or(false);
            if !hit {
                bail!("selector {selector:?} matched nothing");
            }
            json!({
                "filled": selector,
                "value": value,
                "result": after_action(&mut chrome, req)?,
            })
        }
        "wait" => {
            let selector = req.selector.as_deref().unwrap_or_default();
            wait_for(&mut chrome, selector, timeout)?;
            json!({
                "found": selector,
                "result": after_action(&mut chrome, req)?,
            })
        }
        "snapshot" => {
            chrome.pump(NETWORK_SETTLE);
            let title = chrome.evaluate("document.title")?;
            let url = chrome.evaluate("location.href")?;
            let text = chrome.evaluate("document.body ? document.body.innerText : ''")?;
            let bytes = chrome.screenshot(req.full_page)?;
            let path = write_output(&req.output, "png", &bytes)?;
            json!({
                "url": url,
                "title": title,
                "text": text.as_str().map(|text| cap(text, 4_000)).unwrap_or_default(),
                "screenshot": path.display().to_string(),
                "requests": request_rows(&chrome)
                    .as_array()
                    .map(|rows| rows.iter().take(30).cloned().collect::<Vec<_>>())
                    .unwrap_or_default(),
            })
        }
        _ => unreachable!("the action list and the match are checked together"),
    };

    if req.json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(&value)?));
    }
    Ok(render(&action, &value))
}

fn render(action: &str, value: &Value) -> String {
    let text = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    match action {
        "dom" | "html" => text(value, "html"),
        "text" => text(value, "text"),
        "title" => format!("{}\n{}", text(value, "title"), text(value, "url")),
        "eval" => match value.get("result") {
            Some(Value::String(text)) => text.clone(),
            Some(other) => serde_json::to_string_pretty(other).unwrap_or_default(),
            None => String::new(),
        },
        "screenshot" | "pdf" => format!(
            "{} ({} bytes)\n",
            text(value, "path"),
            value.get("bytes").and_then(Value::as_u64).unwrap_or(0)
        ),
        "cookies" | "set-cookie" => value
            .get("cookies")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .map(|row| format!("{row}\n"))
                    .collect()
            })
            .unwrap_or_default(),
        "requests" => render_requests(value.get("requests")),
        "console" => value
            .get("console")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .map(|row| format!("{row}\n"))
                    .collect()
            })
            .unwrap_or_default(),
        "links" => value
            .get("links")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .map(|row| {
                        format!(
                            "{}\n    {}",
                            row.get("href").and_then(Value::as_str).unwrap_or("?"),
                            row.get("text").and_then(Value::as_str).unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n"
            })
            .unwrap_or_default(),
        "storage" => serde_json::to_string_pretty(value.get("storage").unwrap_or(&Value::Null))
            .unwrap_or_default(),
        "click" | "fill" | "wait" => serde_json::to_string_pretty(value).unwrap_or_default(),
        "snapshot" => {
            let mut out = String::new();
            out.push_str(&format!("title     {}\n", text(value, "title")));
            out.push_str(&format!("url       {}\n", text(value, "url")));
            out.push_str(&format!("shot      {}\n", text(value, "screenshot")));
            let body = text(value, "text");
            if !body.is_empty() {
                out.push_str("\ntext\n");
                for line in body.lines().take(80) {
                    out.push_str(&format!("  {line}\n"));
                }
            }
            let requests = render_requests(value.get("requests"));
            if !requests.is_empty() {
                out.push_str("\nrequests\n");
                for line in requests.lines().take(30) {
                    out.push_str(&format!("  {line}\n"));
                }
            }
            out
        }
        _ => String::new(),
    }
}

fn render_requests(rows: Option<&Value>) -> String {
    let Some(rows) = rows.and_then(Value::as_array) else {
        return String::new();
    };
    let mut out = String::new();
    for row in rows.iter().take(ROW_LIMIT) {
        let method = row.get("method").and_then(Value::as_str).unwrap_or("?");
        let status = row
            .get("status")
            .and_then(Value::as_u64)
            .map(|status| status.to_string())
            .unwrap_or_else(|| {
                row.get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("-")
                    .to_string()
            });
        let kind = row.get("type").and_then(Value::as_str).unwrap_or("");
        let size = row
            .get("bytes")
            .and_then(Value::as_u64)
            .map(human_size)
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{method:7} {status:5} {size:>8} {kind:9} {}\n",
            row.get("url").and_then(Value::as_str).unwrap_or("?")
        ));
    }
    if rows.len() > ROW_LIMIT {
        out.push_str(&format!("... {} more\n", rows.len() - ROW_LIMIT));
    }
    out
}

fn request_rows(chrome: &Chrome) -> Value {
    let mut rows: Vec<Value> = Vec::new();
    // Events arrive interleaved; requestId is the join key.
    for event in &chrome.events {
        let method = event.get("method").and_then(Value::as_str).unwrap_or("");
        let params = event.get("params").unwrap_or(&Value::Null);
        let id = params
            .get("requestId")
            .and_then(Value::as_str)
            .unwrap_or("");
        match method {
            "Network.requestWillBeSent" => {
                let request = params.get("request").unwrap_or(&Value::Null);
                rows.push(json!({
                    "id": id,
                    "method": request.get("method").and_then(Value::as_str).unwrap_or("?"),
                    "url": request.get("url").and_then(Value::as_str).unwrap_or("?"),
                    "type": params.get("type").and_then(Value::as_str).unwrap_or("Other"),
                    "status": Value::Null,
                    "bytes": Value::Null,
                    "post": request.get("postData").cloned().unwrap_or(Value::Null),
                }));
            }
            "Network.responseReceived" => {
                let response = params.get("response").unwrap_or(&Value::Null);
                if let Some(row) = row_by_id(&mut rows, id) {
                    row["status"] = response.get("status").cloned().unwrap_or(Value::Null);
                    row["mime"] = response.get("mimeType").cloned().unwrap_or(Value::Null);
                    row["fromCache"] = response
                        .get("fromDiskCache")
                        .or_else(|| response.get("fromServiceWorker"))
                        .cloned()
                        .unwrap_or(json!(false));
                }
            }
            "Network.loadingFinished" => {
                if let Some(row) = row_by_id(&mut rows, id) {
                    row["bytes"] = params
                        .get("encodedDataLength")
                        .cloned()
                        .unwrap_or(Value::Null);
                }
            }
            "Network.loadingFailed" => {
                if let Some(row) = row_by_id(&mut rows, id) {
                    row["error"] = params
                        .get("errorText")
                        .cloned()
                        .unwrap_or_else(|| json!("failed"));
                }
            }
            _ => {}
        }
    }
    Value::Array(rows)
}

fn row_by_id<'a>(rows: &'a mut [Value], id: &str) -> Option<&'a mut Value> {
    rows.iter_mut()
        .rev()
        .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
}

fn console_rows(chrome: &Chrome) -> Value {
    let mut rows: Vec<String> = Vec::new();
    for event in &chrome.events {
        match event.get("method").and_then(Value::as_str) {
            Some("Runtime.consoleAPICalled") => {
                let params = event.get("params").unwrap_or(&Value::Null);
                let level = params.get("type").and_then(Value::as_str).unwrap_or("log");
                let args: Vec<String> = params
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|args| args.iter().map(describe_value).collect())
                    .unwrap_or_default();
                rows.push(format!("{level:8} {}", args.join(" ")));
            }
            Some("Log.entryAdded") => {
                let entry = event
                    .get("params")
                    .and_then(|params| params.get("entry"))
                    .unwrap_or(&Value::Null);
                let level = entry.get("level").and_then(Value::as_str).unwrap_or("info");
                let text = entry.get("text").and_then(Value::as_str).unwrap_or("");
                let where_ = entry
                    .get("url")
                    .and_then(Value::as_str)
                    .map(|url| {
                        let line = entry.get("lineNumber").and_then(Value::as_u64).unwrap_or(0);
                        format!(" ({url}:{line})")
                    })
                    .unwrap_or_default();
                rows.push(format!("{level:8} {text}{where_}"));
            }
            _ => {}
        }
    }
    Value::Array(rows.into_iter().map(Value::String).collect())
}

fn describe_value(value: &Value) -> String {
    if let Some(text) = value.get("value").and_then(Value::as_str) {
        return text.to_string();
    }
    if let Some(text) = value.get("value") {
        return text.to_string();
    }
    // An object has no `value`; the console event carries a small `preview`
    // instead, and `Object` says nothing about what was logged.
    if let Some(preview) = value.get("preview") {
        return describe_preview(preview);
    }
    value
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string()
}

fn describe_preview(preview: &Value) -> String {
    let subtype = preview.get("subtype").and_then(Value::as_str).unwrap_or("");
    let overflow = preview
        .get("overflow")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let properties = preview
        .get("properties")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let render = |property: &Value| {
        let key = property.get("name").and_then(Value::as_str).unwrap_or("");
        let kind = property.get("type").and_then(Value::as_str).unwrap_or("");
        let text = property
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| "…".to_string());
        if kind == "string" {
            format!("{key}: {text:?}")
        } else {
            format!("{key}: {text}")
        }
    };
    let mut parts: Vec<String> = properties.iter().map(render).collect();
    if overflow {
        parts.push("…".to_string());
    }
    if subtype == "array" {
        // An array's preview names its properties "0", "1", … — the names are
        // noise, the values are the array.
        let values: Vec<String> = properties
            .iter()
            .map(|property| {
                property
                    .get("value")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| "…".to_string())
            })
            .collect();
        let mut values = values;
        if overflow {
            values.push("…".to_string());
        }
        return format!("[{}]", values.join(", "));
    }
    if parts.is_empty() {
        return preview
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("{}")
            .to_string();
    }
    format!("{{ {} }}", parts.join(", "))
}

fn render_cookies(cookies: &Value) -> Value {
    let mut rows: Vec<String> = Vec::new();
    for cookie in cookies.as_array().into_iter().flatten() {
        let name = cookie.get("name").and_then(Value::as_str).unwrap_or("?");
        let value = cookie.get("value").and_then(Value::as_str).unwrap_or("");
        let domain = cookie.get("domain").and_then(Value::as_str).unwrap_or("");
        let path = cookie.get("path").and_then(Value::as_str).unwrap_or("/");
        let mut flags = Vec::new();
        if cookie
            .get("secure")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            flags.push("secure");
        }
        if cookie
            .get("httpOnly")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            flags.push("httpOnly");
        }
        if let Some(same) = cookie.get("sameSite").and_then(Value::as_str) {
            if same != "None" {
                flags.push(same);
            }
        }
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(" "))
        };
        rows.push(format!("{name}={value}  {domain}{path}{flags}"));
    }
    Value::Array(rows.into_iter().map(Value::String).collect())
}

/// `js`, when given alongside an interaction, runs after it.
///
/// Clicking something that then updates the page is the normal case, and a
/// tool that only reports "clicked" makes the caller start a second browser to
/// see what happened. This keeps the answer in the same call.
fn after_action(chrome: &mut Chrome, req: &Request) -> Result<Value> {
    match req.js.as_deref().filter(|js| !js.trim().is_empty()) {
        Some(js) => chrome.evaluate(js),
        None => Ok(Value::Null),
    }
}

fn wait_for(chrome: &mut Chrome, selector: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let found = chrome.evaluate(&format!(
            "!!document.querySelector({})",
            js_string(selector)
        ))?;
        if found.as_bool().unwrap_or(false) {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!(
                "selector {selector:?} did not appear within {} ms",
                timeout.as_millis()
            );
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn check_scheme(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    for allowed in ["http://", "https://", "data:", "about:", "file://"] {
        if lower.starts_with(allowed) {
            return Ok(());
        }
    }
    bail!(
        "refusing {url:?}: the browser tool opens http, https, data, about or file, \
         not other schemes"
    )
}

fn parse_headers(specs: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for spec in specs {
        let (name, value) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("header {spec:?} is not `Name: value`"))?;
        let name = name.trim();
        if name.is_empty() {
            bail!("header {spec:?} has no name");
        }
        if name.eq_ignore_ascii_case("host") {
            // CDP drops it silently, so say so instead.
            bail!("a Host header cannot be changed through the browser");
        }
        out.push((name.to_string(), value.trim().to_string()));
    }
    Ok(out)
}

fn write_output(output: &Option<String>, extension: &str, bytes: &[u8]) -> Result<PathBuf> {
    let path = match output {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            }
        }
        None => {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            crate::cache_dir("browser").join(format!("page-{stamp}.{extension}"))
        }
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    std::fs::write(&path, bytes).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(path)
}

fn cap(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    // Cut on a character boundary, not mid-UTF-8.
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n... truncated at {limit} bytes", &text[..end])
}

fn human_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1} kB", bytes as f64 / 1024.0);
    }
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// A JavaScript string literal, escaped well enough for a selector or a value.
fn js_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_must_use_a_scheme_the_browser_understands() {
        assert!(check_scheme("https://example.com").is_ok());
        assert!(check_scheme("http://127.0.0.1:8080/x").is_ok());
        assert!(check_scheme("data:text/html,hi").is_ok());
        assert!(check_scheme("javascript:alert(1)").is_err());
        assert!(check_scheme("ftp://example.com").is_err());
    }

    #[test]
    fn selectors_are_escaped_for_javascript() {
        assert_eq!(js_string(r#"a[href="x"]"#), r#""a[href=\"x\"]""#);
        assert_eq!(js_string("line\nbreak"), r#""line\nbreak""#);
    }

    #[test]
    fn headers_are_parsed_and_host_is_refused() {
        let parsed =
            parse_headers(&["X-Token: abc".to_string(), "Accept: */*".to_string()]).unwrap();
        assert_eq!(parsed[0], ("X-Token".to_string(), "abc".to_string()));
        assert!(parse_headers(&["X".to_string()]).is_err());
        assert!(parse_headers(&["Host: evil".to_string()]).is_err());
    }

    #[test]
    fn long_text_is_cut_on_a_character_boundary() {
        let text = "привет".repeat(10);
        let cut = cap(&text, 9);
        assert!(cut.ends_with("truncated at 9 bytes"));
        assert!(cut.starts_with('п'));
    }

    #[test]
    fn sizes_are_readable() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 kB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MB");
    }

    #[test]
    fn a_missing_action_names_the_one_that_is_wrong() {
        let req = Request {
            url: "https://example.com".to_string(),
            action: "screenshot-all".to_string(),
            ..Request::default()
        };
        let err = run(&req).unwrap_err().to_string();
        assert!(err.contains("unknown action"));
    }

    #[test]
    fn actions_that_need_a_selector_say_so_before_starting_a_browser() {
        for action in ["click", "fill", "wait"] {
            let req = Request {
                url: "https://example.com".to_string(),
                action: action.to_string(),
                ..Request::default()
            };
            let err = run(&req).unwrap_err().to_string();
            assert!(err.contains("selector"), "{action}: {err}");
        }
    }

    /// The one test that starts a browser. It is skipped when Chrome is not
    /// installed, because a missing browser is a valid machine, not a failure.
    #[test]
    fn a_page_is_read_through_a_real_browser() {
        if crate::cdp::browser_binary().is_none() {
            eprintln!("no browser found; skipping the live test");
            return;
        }
        let req = Request {
            url: "data:text/html,<title>t</title><body><h1>live</h1><script>\
                  localStorage.setItem('k','v')</script>"
                .to_string(),
            action: "snapshot".to_string(),
            output: Some(
                std::env::temp_dir()
                    .join(format!("rekit-browser-test-{}.png", std::process::id()))
                    .display()
                    .to_string(),
            ),
            timeout_ms: 20_000,
            ..Request::default()
        };
        let report = run(&req).expect("the browser should open a data: url");
        assert!(report.contains("live"), "{report}");
        let shot = req.output.clone().unwrap();
        assert!(PathBuf::from(&shot).is_file());
        assert_eq!(
            std::fs::read(&shot)
                .map(|bytes| bytes[..4].to_vec())
                .unwrap(),
            b"\x89PNG".to_vec()
        );
        let _ = std::fs::remove_file(&shot);
    }
}
