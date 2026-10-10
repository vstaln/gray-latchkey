//! gray-latchkey — inject stored credentials into curl calls.
//!
//! Port of pi's `latchkey` extension. `tool/before` on `bash` rewrites curl
//! invocations that target a configured host, inserting
//! `-H '<Header>: <prefix><key>'` after the `curl` token — unless the
//! invocation already carries that header. `tool/after` scrubs every known
//! secret value out of the tool result so the echoed command (and any curl
//! verbose output) never lands a key in the transcript.
//!
//! Hosts come from `~/.gray/latchkey/config.json`:
//!
//! ```json
//! {"hosts": {
//!   "api.example.com": {"header": "Authorization", "prefix": "Bearer ",
//!                        "key_env": "EXAMPLE_TOKEN"},
//!   "internal.lan":    {"header": "X-Api-Key", "key": "literal-not-advised"}
//! }}
//! ```
//!
//! `key_env` (read at call time) is preferred; `key` stores a secret in
//! plaintext config — supported, discouraged. Values are never logged.
//!
//! The rewrite is deliberately naive: a curl "window" runs from the `curl`
//! token to the next `;` `|` `&` or newline. Quoted separators can shrink a
//! window and cause a *missed* injection — fail-open, never a leak.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde_json::{Value, json};

/// Shorter secrets than this are still injected but can't be scrubbed from
/// results safely (a 2-char replace would mangle real output).
const MIN_SCRUB_LEN: usize = 4;

fn manifest() -> Value {
    json!({
        "name": "latchkey",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "2.0",
        "tools": [],
        "commands": ["/latchkey"],
        "hooks": ["tool/before", "tool/after"],
    })
}

fn config_path() -> PathBuf {
    std::env::var_os("GRAY_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".gray")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("latchkey")
        .join("config.json")
}

/// One configured host with its credential resolved, ready to inject.
struct Rule {
    host: String,
    header: String,
    prefix: String,
    value: String,
}

/// Read config and resolve each host's key. `key_env` wins over `key`;
/// hosts whose key resolves empty are skipped (reported by /latchkey).
fn rules() -> Vec<Rule> {
    let Ok(text) = std::fs::read_to_string(config_path()) else {
        return Vec::new();
    };
    let Ok(cfg) = serde_json::from_str::<Value>(&text) else {
        eprintln!("gray-latchkey: {} isn't valid JSON", config_path().display());
        return Vec::new();
    };
    let Some(hosts) = cfg.get("hosts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (host, spec) in hosts {
        let header = spec
            .get("header")
            .and_then(Value::as_str)
            .unwrap_or("Authorization")
            .to_string();
        let prefix = spec
            .get("prefix")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let value = spec
            .get("key_env")
            .and_then(Value::as_str)
            .and_then(|v| std::env::var(v).ok())
            .or_else(|| spec.get("key").and_then(Value::as_str).map(String::from))
            .unwrap_or_default();
        if !host.is_empty() && !value.is_empty() {
            out.push(Rule {
                host: host.clone(),
                header,
                prefix,
                value,
            });
        }
    }
    out
}

/// Shell words that may precede the real command without making `curl` an
/// argument (`sudo curl`, `FOO=1 curl`, `env A=1 curl`, `time curl`).
fn is_prefix_word(w: &str) -> bool {
    w.contains('=')
        || matches!(w, "sudo" | "command" | "env" | "time" | "nohup" | "exec" | "builtin")
}

/// Is the token starting at `pos` in command position — the first
/// non-prefix word after a command boundary (`;` `|` `&` `(` newline or
/// start)? `echo curl host` is NOT: `curl` there is an argument, and
/// injecting would print the secret rather than send it.
fn is_command_position(cmd: &str, pos: usize) -> bool {
    let bytes = cmd.as_bytes();
    // `pos` may sit mid-word (`/usr/bin/curl`); back up to the word start.
    let mut ws = pos;
    while ws > 0
        && !matches!(bytes[ws - 1], b' ' | b'\t' | b';' | b'|' | b'&' | b'(' | b'\n')
    {
        ws -= 1;
    }
    let seg_start = cmd[..ws]
        .rfind([';', '|', '&', '\n', '('])
        .map(|i| i + 1)
        .unwrap_or(0);
    cmd[seg_start..ws]
        .split_whitespace()
        .all(is_prefix_word)
}

/// Next `curl` token sitting in command position: word-boundaried (a `/`
/// before it is fine — `/usr/bin/curl` counts) and followed by whitespace,
/// a separator, or end.
fn find_curl(cmd: &str, from: usize) -> Option<usize> {
    let bytes = cmd.as_bytes();
    let mut i = from;
    while i + 4 <= bytes.len() {
        // Byte-compare, never a str slice: `i` walks every index, so a
        // `cmd[i..i+4]` slice panics when `i+4` lands inside a multi-byte
        // char; a unicode command killed the sidecar mid-scan and every
        // later tool call got "plugin policy unavailable".
        if bytes[i..i + 4] == *b"curl" {
            let before_ok = i == 0
                || matches!(bytes[i - 1], b' ' | b'\t' | b';' | b'|' | b'&' | b'(' | b'/' | b'\n');
            let after_ok = i + 4 == bytes.len()
                || matches!(bytes[i + 4], b' ' | b'\t' | b'\n' | b';' | b'|' | b'&');
            if before_ok && after_ok && is_command_position(cmd, i) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// End of the curl window: next `;` `|` `&` or newline (naive — quoted
/// separators shrink the window, which fails open).
fn window_end(cmd: &str, from: usize) -> usize {
    cmd[from..]
        .find([';', '|', '&', '\n'])
        .map(|d| from + d)
        .unwrap_or(cmd.len())
}

/// Does the window already carry this header? Any `Name:` mention counts —
/// false positives just mean we don't inject.
fn has_header(window: &str, name: &str) -> bool {
    window
        .to_ascii_lowercase()
        .contains(&format!("{}:", name.to_ascii_lowercase()))
}

/// `'…'` with embedded `'` escaped as `'\''`.
fn shell_sq(s: &str) -> String {
    s.replace('\'', r"'\''")
}

/// Insert `-H '<Header>: <prefix><value>'` after every `curl` token whose
/// window mentions a configured host and lacks that header.
fn inject(cmd: &str, rules: &[Rule]) -> Option<String> {
    let mut out = String::with_capacity(cmd.len() + 64);
    let mut i = 0;
    let mut changed = false;
    while let Some(pos) = find_curl(cmd, i) {
        let end = window_end(cmd, pos + 4);
        let window = &cmd[pos..end];
        out.push_str(&cmd[i..pos + 4]);
        for r in rules {
            if window.contains(&r.host) && !has_header(window, &r.header) {
                out.push_str(&format!(
                    " -H '{}: {}{}'",
                    shell_sq(&r.header),
                    shell_sq(&r.prefix),
                    shell_sq(&r.value)
                ));
                changed = true;
            }
        }
        i = pos + 4;
    }
    out.push_str(&cmd[i..]);
    changed.then_some(out)
}

fn tool_before(params: &Value) -> Value {
    if params.get("name").and_then(Value::as_str) != Some("bash") {
        return json!({"decision": "allow"});
    }
    let command = params
        .get("args")
        .and_then(|a| a.get("command"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if command.is_empty() || !command.contains("curl") {
        return json!({"decision": "allow"});
    }
    match inject(command, &rules()) {
        Some(new) => json!({
            "decision": "modify",
            "args": { "command": new }
        }),
        None => json!({"decision": "allow"}),
    }
}

/// Scrub every known secret out of the result — the echoed command and any
/// curl `-v` chatter included. Only the value is replaced, so the echo still
/// shows `-H 'Authorization: Bearer [redacted-by-latchkey]'`.
fn tool_after(params: &Value) -> Value {
    let content = params.get("content").and_then(Value::as_str).unwrap_or("");
    if content.is_empty() {
        return json!({});
    }
    let mut out = content.to_string();
    for r in rules() {
        if r.value.len() >= MIN_SCRUB_LEN {
            out = out.replace(&r.value, "[redacted-by-latchkey]");
        }
    }
    if out == content {
        json!({})
    } else {
        json!({ "content": out })
    }
}

/// `/latchkey` — configured hosts and whether each key resolves. Values are
/// never shown.
fn run_command(argv: &[&str]) -> String {
    if !argv.is_empty() {
        return "usage: /latchkey".into();
    }
    let Ok(text) = std::fs::read_to_string(config_path()) else {
        return format!(
            "gray-latchkey {} — no config. Write {} like:\n\
             {{\"hosts\": {{\"api.example.com\": {{\"header\": \"Authorization\", \
             \"prefix\": \"Bearer \", \"key_env\": \"EXAMPLE_TOKEN\"}}}}}}",
            env!("CARGO_PKG_VERSION"),
            config_path().display()
        );
    };
    let Ok(cfg) = serde_json::from_str::<Value>(&text) else {
        return format!("{} isn't valid JSON", config_path().display());
    };
    let mut out = format!(
        "gray-latchkey {} — {}\n",
        env!("CARGO_PKG_VERSION"),
        config_path().display()
    );
    let Some(hosts) = cfg.get("hosts").and_then(Value::as_object) else {
        out.push_str("no hosts configured");
        return out;
    };
    if hosts.is_empty() {
        out.push_str("no hosts configured");
        return out;
    }
    for (host, spec) in hosts {
        let header = spec
            .get("header")
            .and_then(Value::as_str)
            .unwrap_or("Authorization");
        let (src, set) = if let Some(v) = spec.get("key_env").and_then(Value::as_str) {
            (
                format!("env:{v}"),
                std::env::var(v).map(|s| !s.is_empty()).unwrap_or(false),
            )
        } else if spec.get("key").and_then(Value::as_str).is_some() {
            ("inline".to_string(), true)
        } else {
            ("none".to_string(), false)
        };
        out.push_str(&format!(
            "  {host:<28} {header:<16} key {src} ({})\n",
            if set { "set" } else { "MISSING" }
        ));
    }
    out.trim_end().to_string()
}

/// One request → `Some(reply)`, or `None` for notifications. The bool asks
/// the loop to exit after writing the reply.
fn handle(req: &Value) -> (Option<Value>, bool) {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let Some(id) = id else {
        return (None, method == "plugin/shutdown");
    };
    let result = match method {
        "plugin/manifest" => manifest(),
        "tool/before" => tool_before(&params),
        "tool/after" => tool_after(&params),
        "command/run" => {
            let argv: Vec<&str> = params
                .get("argv")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            json!({ "text": run_command(&argv) })
        }
        "plugin/shutdown" => return (Some(json!({ "id": id, "result": {} })), true),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return (Some(json!({ "id": id, "error": error })), false);
        }
    };
    (Some(json!({ "id": id, "result": result })), false)
}

/// Sidecar entry: `gray-latchkey manifest` prints the manifest, otherwise
/// serve JSON-lines requests on stdin until EOF or `plugin/shutdown`.
pub fn run() -> std::io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest());
        return Ok(());
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let Ok(req) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let (reply, exit) = handle(&req);
        if let Some(reply) = reply {
            writeln!(stdout, "{reply}")?;
            stdout.flush()?;
        }
        if exit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static CTR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// Run `body` with GRAY_HOME at a fresh temp dir holding `cfg` as
    /// latchkey/config.json. Serialized: env vars are process-global.
    fn with_config(cfg: &str, body: impl FnOnce(&Path)) {
        let _g = LOCK.lock().unwrap();
        let n = CTR.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let home = std::env::temp_dir().join(format!("gray-latchkey-test-{n}"));
        let _ = std::fs::remove_dir_all(&home);
        let dir = home.join("latchkey");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), cfg).unwrap();
        unsafe { std::env::set_var("GRAY_HOME", &home) };
        body(&home);
        let _ = std::fs::remove_dir_all(&home);
    }

    const CFG: &str = r#"{"hosts": {
        "api.example.com": {"header": "Authorization", "prefix": "Bearer ",
                             "key": "sk-test-1234567890"},
        "internal.lan":    {"header": "X-Api-Key", "key": "ik-abc"}
    }}"#;

    fn call(method: &str, params: Value) -> Value {
        handle(&json!({ "id": 1, "method": method, "params": params }))
            .0
            .unwrap()
    }

    fn before(command: &str) -> Value {
        call(
            "tool/before",
            json!({"name": "bash", "args": {"command": command}, "session": {"id": "s"}}),
        )["result"]
            .clone()
    }

    #[test]
    fn manifest_shape() {
        let m = call("plugin/manifest", Value::Null)["result"].clone();
        assert_eq!(m["name"], "latchkey");
        assert_eq!(m["hooks"], json!(["tool/before", "tool/after"]));
        assert_eq!(m["commands"], json!(["/latchkey"]));
    }

    #[test]
    fn injects_header_for_configured_host() {
        with_config(CFG, |_| {
            let r = before("curl -s https://api.example.com/v1/me");
            assert_eq!(r["decision"], "modify");
            let cmd = r["args"]["command"].as_str().unwrap();
            assert_eq!(
                cmd,
                "curl -H 'Authorization: Bearer sk-test-1234567890' -s https://api.example.com/v1/me"
            );
        });
    }

    #[test]
    fn skips_unrelated_hosts_and_non_bash() {
        with_config(CFG, |_| {
            assert_eq!(before("curl -s https://other.io")["decision"], "allow");
            // `curl` as an echo argument is not an invocation — no inject.
            assert_eq!(before("echo curl api.example.com | wc")["decision"], "allow");
            let r = call(
                "tool/before",
                json!({"name": "read", "args": {"command": "curl api.example.com"}}),
            );
            assert_eq!(r["result"]["decision"], "allow");
        });
    }

    #[test]
    fn respects_existing_header() {
        with_config(CFG, |_| {
            let r = before("curl -H 'Authorization: Bearer manual' https://api.example.com");
            assert_eq!(r["decision"], "allow");
        });
    }

    #[test]
    fn injects_per_segment_only() {
        with_config(CFG, |_| {
            let r = before("curl api.example.com ; curl other.io");
            let cmd = r["args"]["command"].as_str().unwrap();
            assert!(cmd.starts_with("curl -H 'Authorization:"));
            assert!(cmd.ends_with("curl other.io"));
        });
    }

    #[test]
    fn env_key_resolves() {
        with_config(
            r#"{"hosts": {"h.io": {"header": "X-T", "key_env": "LATCHKEY_TEST_K"}}}"#,
            |_| {
                unsafe { std::env::set_var("LATCHKEY_TEST_K", "envval-99") };
                let cmd = before("curl h.io/x")["args"]["command"].as_str().unwrap().to_string();
                assert!(cmd.contains("-H 'X-T: envval-99'"), "{cmd}");
                unsafe { std::env::remove_var("LATCHKEY_TEST_K") };
                assert_eq!(before("curl h.io/x")["decision"], "allow");
            },
        );
    }

    #[test]
    fn after_scrubs_secret_from_echo() {
        with_config(CFG, |_| {
            let content = "$ curl -H 'Authorization: Bearer sk-test-1234567890' api.example.com\nok";
            let r = call(
                "tool/after",
                json!({"name": "bash", "content": content, "session": {"id": "s"}}),
            );
            let out = r["result"]["content"].as_str().unwrap();
            assert!(out.contains("Bearer [redacted-by-latchkey]"));
            assert!(!out.contains("sk-test-1234567890"));

            let clean = call(
                "tool/after",
                json!({"name": "bash", "content": "no secrets", "session": {"id": "s"}}),
            );
            assert_eq!(clean["result"], json!({}));
        });
    }

    #[test]
    fn latchkey_lists_hosts_never_values() {
        with_config(CFG, |_| {
            let r = call(
                "command/run",
                json!({"name": "/latchkey", "argv": [], "session": {"id": "s"}}),
            );
            let text = r["result"]["text"].as_str().unwrap();
            assert!(text.contains("api.example.com") && text.contains("X-Api-Key"));
            assert!(!text.contains("sk-test-1234567890") && !text.contains("ik-abc"));
        });
    }

    #[test]
    fn unicode_near_curl_does_not_panic() {
        // lib.rs:143 used to slice cmd[i..i+4] by bytes; a command whose
        // multibyte char sat inside that window panicked the sidecar and
        // the host denied the tool as "plugin policy unavailable".
        with_config(CFG, |_| {
            let r = before("echo 'a \u{2192} b' ; curl api.example.com/x");
            let cmd = r["args"]["command"].as_str().unwrap();
            assert!(cmd.contains("-H '"), "{cmd}");
        });
    }

    #[test]
    fn shutdown_replies_then_exits() {
        let (reply, exit) = handle(&json!({ "id": 2, "method": "plugin/shutdown" }));
        assert!(reply.is_some() && exit);
    }
}
