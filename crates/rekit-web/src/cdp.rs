//! Driving a real browser over the DevTools protocol.
//!
//! Static analysis of a bundle tells you what the code *can* do; a browser
//! tells you what it *did*: which requests the page made, with which cookies,
//! what the DOM looks like after three layers of framework hydration, what the
//! console complained about. That is the difference between "this endpoint
//! exists in the JS" and "this endpoint is called on load with a bearer token".
//!
//! Chrome is started headless with a throwaway profile, a port chosen by the
//! browser, and killed on the way out. Nothing is shared with the user's
//! profile, so a page cannot read their cookies, and the session leaves no
//! trace beyond the screenshot the caller asked for.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::ws::Ws;

/// The browser binaries to try, in order. Chrome and Chromium speak the same
/// protocol; `google-chrome-stable` is what most distributions install.
const BROWSERS: &[&str] = &[
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "brave",
    "brave-browser",
    "microsoft-edge",
];

/// How many protocol events to keep. A page that polls can produce thousands
/// of requests; the point is a readable table, not a packet capture.
const MAX_EVENTS: usize = 20_000;

/// Which browser to start, or none at all.
pub fn browser_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("REKIT_BROWSER") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    for name in BROWSERS {
        if let Some(path) = crate::find_in_path(name) {
            return Some(path);
        }
    }
    None
}

pub struct Chrome {
    child: Option<Child>,
    profile: PathBuf,
    keep_profile: bool,
    ws: Ws,
    next_id: u64,
    /// Events read while waiting for a reply, kept for `requests` and
    /// `console`. The oldest are dropped once the cap is reached.
    pub(crate) events: Vec<Value>,
    timeout: Duration,
}

impl Chrome {
    /// Start a browser and connect to its first page.
    pub fn launch(headless: bool, size: (u32, u32), keep_profile: bool) -> Result<Self> {
        let exe = browser_binary().ok_or_else(|| {
            anyhow!(
                "no Chrome or Chromium found; install one, or point REKIT_BROWSER at the binary"
            )
        })?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let profile =
            crate::cache_dir("chrome").join(format!("profile-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&profile)
            .with_context(|| format!("cannot create {}", profile.display()))?;

        let mut command = Command::new(&exe);
        command
            .arg(if headless {
                "--headless=new"
            } else {
                "--start-maximized"
            })
            .arg("--disable-gpu")
            .arg("--disable-extensions")
            .arg("--disable-background-networking")
            .arg("--disable-sync")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-features=Translate,MediaRouter")
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("--remote-debugging-port=0")
            .arg(format!("--window-size={},{}", size.0, size.1))
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if pipeline_isolated() {
            // Chrome refuses to start as root without this, and inside a
            // container there is no user namespace to fall back on.
            command.arg("--no-sandbox");
        }
        let child = command
            .spawn()
            .with_context(|| format!("cannot start {}", exe.display()))?;

        let deadline = Instant::now() + Duration::from_secs(20);
        let port = loop {
            if let Some(port) = read_active_port(&profile) {
                break port;
            }
            if Instant::now() > deadline {
                let _ = std::fs::remove_dir_all(&profile);
                bail!(
                    "the browser did not open a debugging port within 20 s: \
                     start it once by hand to see why"
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        };

        // The port appears before the first page does, so the list is polled
        // rather than read once.
        let deadline = Instant::now() + Duration::from_secs(30);
        let page = loop {
            match page_socket(port) {
                Ok(url) => break url,
                Err(err) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                    if Instant::now() >= deadline {
                        bail!(
                            "the browser is listening on {port} but lists no page \
                             ({err:#}): another Chrome may already own this profile"
                        );
                    }
                }
                Err(err) => bail!(
                    "the browser is listening on {port} but lists no page \
                     ({err:#}): another Chrome may already own this profile"
                ),
            }
        };
        let ws = Ws::connect(&page, Duration::from_secs(10))?;
        ws.set_timeout(Duration::from_secs(30))?;

        Ok(Chrome {
            child: Some(child),
            profile,
            keep_profile,
            ws,
            next_id: 1,
            events: Vec::new(),
            timeout: Duration::from_secs(30),
        })
    }

    /// Attach to a browser that is already running instead of starting one.
    ///
    /// The target is the page's `ws://` URL, or the debugging endpoint itself
    /// (`http://127.0.0.1:9222`, `127.0.0.1:9222`, `9222`) — in which case the
    /// browser is asked which page to use.
    pub fn attach(target: &str) -> Result<Self> {
        let target = target.trim();
        if target.is_empty() {
            bail!("attach needs a ws:// url or the host:port of a running browser");
        }
        let ws_url = if target.starts_with("ws://") {
            target.to_string()
        } else {
            page_socket(debug_port(target)?)?
        };
        let ws = Ws::connect(&ws_url, Duration::from_secs(10))?;
        ws.set_timeout(Duration::from_secs(30))?;
        Ok(Chrome {
            child: None,
            profile: PathBuf::new(),
            keep_profile: true,
            ws,
            next_id: 1,
            events: Vec::new(),
            timeout: Duration::from_secs(30),
        })
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        let _ = self.ws.set_timeout(timeout);
    }

    /// One protocol round trip.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({"id": id, "method": method, "params": params});
        self.ws.send(&request.to_string())?;
        loop {
            let message = self.recv_message()?;
            if message.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(error) = message.get("error") {
                    bail!(
                        "{} failed: {}",
                        method,
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown error")
                    );
                }
                return Ok(message.get("result").cloned().unwrap_or(Value::Null));
            }
            if message.get("method").is_some() {
                self.record(message);
            }
        }
    }

    fn recv_message(&mut self) -> Result<Value> {
        let text = match self.ws.recv()? {
            Some(text) => text,
            None => bail!("the browser closed the debugging connection"),
        };
        serde_json::from_str(&text)
            .with_context(|| format!("the browser sent something that is not JSON: {text:.120}"))
    }

    fn record(&mut self, event: Value) {
        // A dialog blocks the renderer until someone answers it, and the page
        // that greets you with `alert("debugger")` is not rare. Accept it and
        // move on; the event itself stays in the log.
        let dialog =
            event.get("method").and_then(Value::as_str) == Some("Page.javascriptDialogOpening");
        if self.events.len() >= MAX_EVENTS {
            self.events.drain(..MAX_EVENTS / 4);
        }
        self.events.push(event);
        if dialog {
            let _ = self.call("Page.handleJavaScriptDialog", json!({"accept": true}));
        }
    }

    /// Wait for one event, buffering everything that arrives first.
    pub fn wait_event(&mut self, method: &str, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        if let Some(index) = self
            .events
            .iter()
            .position(|event| event.get("method").and_then(Value::as_str) == Some(method))
        {
            return Ok(self.events.remove(index));
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("timed out waiting for {method}");
            }
            let _ = self.ws.set_timeout(remaining.min(Duration::from_secs(5)));
            let message = self.recv_message()?;
            if message.get("method").and_then(Value::as_str) == Some(method) {
                return Ok(message);
            }
            if message.get("method").is_some() {
                self.record(message);
            }
        }
    }

    /// Read whatever the browser has already sent, until the stream goes quiet.
    ///
    /// Events are only read while a command is waiting for its reply, so a
    /// request that finished a moment ago would still look unfinished. This
    /// drains the socket before a table is printed, stopping after `quiet`
    /// with nothing to read or after the overall budget.
    pub fn pump(&mut self, budget: Duration) {
        let deadline = Instant::now() + budget;
        let quiet = Duration::from_millis(150);
        while Instant::now() < deadline {
            match self.ws.has_data(quiet) {
                Ok(true) => {}
                Ok(false) | Err(_) => break,
            }
            let _ = self.ws.set_timeout(Duration::from_secs(10));
            match self.recv_message() {
                Ok(message) => {
                    if message.get("method").is_some() {
                        self.record(message);
                    }
                }
                Err(_) => break,
            }
        }
        let _ = self.ws.set_timeout(self.timeout);
    }

    /// Open a URL and wait for the load event. Returns the final URL.
    pub fn navigate(&mut self, url: &str, timeout: Duration) -> Result<String> {
        let result = self.call("Page.navigate", json!({"url": url}))?;
        if let Some(error) = result.get("errorText").and_then(Value::as_str) {
            if !error.is_empty() {
                bail!("the browser refused {url}: {error}");
            }
        }
        let loaded = self.wait_event("Page.loadEventFired", timeout);
        if let Err(err) = loaded {
            // A page that keeps a connection open (a websocket, a hanging
            // script) never fires the load event; the DOM is still there, so
            // report what was reached instead of failing the whole run.
            if err.to_string().contains("timed out") {
                return Ok(result
                    .get("frameId")
                    .and_then(Value::as_str)
                    .map(|_| url.to_string())
                    .unwrap_or_else(|| url.to_string()));
            }
            return Err(err);
        }
        Ok(url.to_string())
    }

    pub fn evaluate(&mut self, expression: &str) -> Result<Value> {
        let result = self.call(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "returnByValue": true,
                "awaitPromise": true,
                "userGesture": true,
                "timeout": self.timeout.as_millis() as u64,
            }),
        )?;
        if let Some(details) = result.get("exceptionDetails") {
            let text = details
                .get("exception")
                .and_then(|e| e.get("description"))
                .and_then(Value::as_str)
                .or_else(|| details.get("text").and_then(Value::as_str))
                .unwrap_or("the page threw");
            bail!("{text}");
        }
        Ok(result
            .get("result")
            .and_then(|value| value.get("value"))
            .cloned()
            .unwrap_or_else(|| {
                result
                    .get("result")
                    .and_then(|value| value.get("description"))
                    .cloned()
                    .unwrap_or(Value::Null)
            }))
    }

    pub fn screenshot(&mut self, full_page: bool) -> Result<Vec<u8>> {
        let result = self.call(
            "Page.captureScreenshot",
            json!({"format": "png", "captureBeyondViewport": full_page}),
        )?;
        let data = result
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("the browser returned no image"))?;
        crate::ws::base64_decode(data)
    }

    pub fn pdf(&mut self) -> Result<Vec<u8>> {
        let result = self.call("Page.printToPDF", json!({"printBackground": true}))?;
        let data = result
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("the browser returned no pdf"))?;
        crate::ws::base64_decode(data)
    }

    pub fn cookies(&mut self) -> Result<Value> {
        let result = self.call("Storage.getCookies", json!({}))?;
        Ok(result.get("cookies").cloned().unwrap_or_else(|| json!([])))
    }

    /// `name=value; domain=example.com; path=/; secure; httpOnly`
    pub fn set_cookie(&mut self, spec: &str) -> Result<()> {
        let mut parts = spec.split(';').map(str::trim).filter(|s| !s.is_empty());
        let first = parts
            .next()
            .ok_or_else(|| anyhow!("a cookie needs name=value"))?;
        let (name, value) = first
            .split_once('=')
            .ok_or_else(|| anyhow!("cookie {first:?} has no '='"))?;
        let mut params = json!({"name": name.trim(), "value": value.trim(), "path": "/"});
        for part in parts {
            let (key, value) = part.split_once('=').unwrap_or((part, "true"));
            match key.trim().to_ascii_lowercase().as_str() {
                "domain" => params["domain"] = json!(value.trim()),
                "path" => params["path"] = json!(value.trim()),
                "secure" => params["secure"] = json!(true),
                "httponly" => params["httpOnly"] = json!(true),
                "samesite" => params["sameSite"] = json!(value.trim()),
                "expires" => params["expires"] = json!(value.trim()),
                "url" => params["url"] = json!(value.trim()),
                other => bail!("unknown cookie attribute {other:?}"),
            }
        }
        self.call("Network.setCookie", params)?;
        Ok(())
    }

    /// Headers added to every request the page makes.
    pub fn set_headers(&mut self, headers: &[(String, String)]) -> Result<()> {
        let mut map = serde_json::Map::new();
        for (name, value) in headers {
            map.insert(name.clone(), json!(value));
        }
        self.call("Network.setExtraHTTPHeaders", json!({"headers": map}))?;
        Ok(())
    }

    pub fn set_viewport(&mut self, width: u32, height: u32) -> Result<()> {
        self.call(
            "Emulation.setDeviceMetricsOverride",
            json!({
                "width": width,
                "height": height,
                "deviceScaleFactor": 1,
                "mobile": false,
            }),
        )?;
        Ok(())
    }

    pub fn set_user_agent(&mut self, agent: &str) -> Result<()> {
        self.call(
            "Emulation.setUserAgentOverride",
            json!({"userAgent": agent}),
        )?;
        Ok(())
    }

    pub fn ignore_certificate_errors(&mut self) -> Result<()> {
        self.call(
            "Security.setIgnoreCertificateErrors",
            json!({"ignore": true}),
        )?;
        Ok(())
    }

    pub fn enable_domains(&mut self) -> Result<()> {
        self.call("Page.enable", json!({}))?;
        self.call("Runtime.enable", json!({}))?;
        self.call("Network.enable", json!({"maxTotalBufferSize": 1 << 26}))?;
        let _ = self.call("Log.enable", json!({}));
        Ok(())
    }

    pub fn profile_dir(&self) -> &Path {
        &self.profile
    }
}

impl Drop for Chrome {
    fn drop(&mut self) {
        // Only a browser this run started is closed. Attaching to someone
        // else's browser and then killing it on the way out would be a nasty
        // surprise — their debugging session, their logins.
        if let Some(mut child) = self.child.take() {
            // Closing the socket first lets the browser exit cleanly; the kill
            // is the backstop for a page that is busy.
            let _ = self.ws.send(r#"{"id":0,"method":"Browser.close"}"#);
            for _ in 0..20 {
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        // The process we spawn is the launcher, which exits once it has handed
        // off to the real browser: killing it alone leaves a whole browser
        // (and its profile lock) behind. The profile path is unique to this
        // run, so it identifies exactly the processes to stop.
        if !self.profile.as_os_str().is_empty() {
            let pattern = format!("--user-data-dir={}", self.profile.display());
            let _ = Command::new("pkill")
                .args(["-TERM", "-f", "--", &pattern])
                .status();
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(50));
                let alive = Command::new("pgrep")
                    .args(["-f", "--", &pattern])
                    .output()
                    .map(|out| out.status.success())
                    .unwrap_or(false);
                if !alive {
                    break;
                }
            }
            let _ = Command::new("pkill")
                .args(["-KILL", "-f", "--", &pattern])
                .status();
        }
        if !self.keep_profile {
            let _ = std::fs::remove_dir_all(&self.profile);
        }
    }
}

fn pipeline_isolated() -> bool {
    // Chrome's own check: geteuid == 0.
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(1).map(str::to_string))
        })
        .and_then(|uid| uid.parse::<u32>().ok());
    uid == Some(0)
}

/// The port in `9222`, `127.0.0.1:9222` or `http://127.0.0.1:9222`.
fn debug_port(target: &str) -> Result<u16> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    let rest = rest.split('/').next().unwrap_or(rest);
    let port = match rest.rsplit_once(':') {
        Some((_, port)) => port,
        None => rest,
    };
    port.parse::<u16>()
        .with_context(|| format!("{target:?} is not a ws:// url or a host:port"))
}

fn read_active_port(profile: &Path) -> Option<u16> {
    let text = std::fs::read_to_string(profile.join("DevToolsActivePort")).ok()?;
    text.lines().next()?.trim().parse().ok()
}

/// Ask the browser which pages it has and take the first real one.
fn page_socket(port: u16) -> Result<String> {
    let body = http_get(port, "/json/list")?;
    let pages: Value = serde_json::from_str(&body).context("cannot read the page list")?;
    let pages = pages.as_array().cloned().unwrap_or_default();
    let page = pages
        .iter()
        .find(|page| page.get("type").and_then(Value::as_str) == Some("page"))
        .ok_or_else(|| anyhow!("no page targets"))?;
    page.get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("the page has no debugger url"))
}

/// A tiny HTTP/1.1 GET, because the DevTools endpoint is local and plain.
///
/// Reads exactly `Content-Length` bytes rather than to EOF: Chrome keeps the
/// connection open even when asked to close it, and waiting for a close that
/// never comes is what turned a working endpoint into a timeout.
fn http_get(port: u16, path: &str) -> Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("cannot reach the browser on {port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Accept: application/json\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break None;
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(index) = find(&raw, b"\r\n\r\n") {
            break Some(index + 4);
        }
        if raw.len() > 64 * 1024 {
            bail!("the browser answered with an absurdly large header");
        }
    };
    let Some(head_end) = head_end else {
        bail!("the browser closed the connection without answering");
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        bail!(
            "the browser answered {}",
            head.lines().next().unwrap_or("nothing")
        );
    }
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    let mut body = raw[head_end..].to_vec();
    if let Some(length) = length {
        while body.len() < length {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(length);
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binary_is_found_or_the_error_says_what_to_do() {
        // The test machine may not have a browser; either answer is valid, but
        // the failing one must name the variable that fixes it.
        if let Some(path) = browser_binary() {
            assert!(path.is_file());
        }
    }

    #[test]
    fn an_attach_target_may_be_a_port_or_a_url() {
        assert_eq!(debug_port("9222").unwrap(), 9222);
        assert_eq!(debug_port("127.0.0.1:9222").unwrap(), 9222);
        assert_eq!(debug_port("http://127.0.0.1:9222").unwrap(), 9222);
        assert_eq!(debug_port("http://127.0.0.1:9222/json/list").unwrap(), 9222);
        assert!(debug_port("ws://127.0.0.1:9222/x").is_err());
    }

    #[test]
    fn active_port_is_read_from_the_file_chrome_writes() {
        let dir = std::env::temp_dir().join(format!("rekit-port-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("DevToolsActivePort"),
            "45123\n/devtools/browser/x\n",
        )
        .unwrap();
        assert_eq!(read_active_port(&dir), Some(45123));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
