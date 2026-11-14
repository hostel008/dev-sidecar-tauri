//! 拦截器管线（对应原版 lib/interceptor）

use crate::dns::is_ip;
use crate::matcher::{is_matched, Captures, DomainMap};
use crate::proxy::http::{split_host_port, HeaderList};
use parking_lot::RwLock;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

// ------------------------------------------------------------------ 请求/响应描述

/// 转发给目标服务器的请求参数（可被拦截器修改）
#[derive(Debug, Clone)]
pub struct RequestOptions {
    pub protocol: String,
    pub method: String,
    pub hostname: String,
    pub port: u16,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// SNI 覆盖值
    pub servername: Option<String>,
    /// 是否跳过证书校验
    pub unverify_ssl: bool,
    pub do_download: bool,
    pub family: u8,
    /// 指定上游 IP（预设 IP 或测速结果）
    pub dns_ip: Option<String>,
    pub dns_label: Option<String>,
    pub original: Option<Box<RequestOptions>>,
}

impl RequestOptions {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        let lower = name.to_lowercase();
        for item in self.headers.iter_mut() {
            if item.0.to_lowercase() == lower {
                item.1 = value.to_string();
                return;
            }
        }
        self.headers.push((name.to_string(), value.to_string()));
    }

    pub fn remove_header(&mut self, name: &str) {
        let lower = name.to_lowercase();
        self.headers.retain(|(k, _)| k.to_lowercase() != lower);
    }

    pub fn url(&self) -> String {
        format!(
            "{}//{}:{}{}",
            self.protocol, self.hostname, self.port, self.path
        )
    }
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub times: u32,
    pub statuses: Vec<u16>,
    pub methods: Vec<String>,
}

/// 默认可重试方法（幂等请求）：既是重试规则的默认值，也用于
/// 「无重试规则时对建连失败再试一次」的兜底判定，避免重复非幂等请求
pub fn default_retry_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()]
}

/// 上游响应头（响应拦截器可原地修改）
#[derive(Debug, Clone)]
pub struct UpstreamHeads {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl UpstreamHeads {
    pub fn get(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }
    pub fn set(&mut self, name: &str, value: &str) {
        let lower = name.to_lowercase();
        for item in self.headers.iter_mut() {
            if item.0.to_lowercase() == lower {
                item.1 = value.to_string();
                return;
            }
        }
        self.headers.push((name.to_string(), value.to_string()));
    }
    pub fn remove(&mut self, name: &str) {
        let lower = name.to_lowercase();
        self.headers.retain(|(k, _)| k.to_lowercase() != lower);
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResponseAppend {
    pub head: String,
    pub body: String,
    pub stop: bool,
}

pub enum InterceptOutcome {
    Continue,
    Handled,
}

/// 单个请求的处理上下文
pub struct InterceptContext {
    pub r_options: RequestOptions,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: HeaderList,
    pub response_status: Option<u16>,
    pub response_body: Option<Vec<u8>>,
    pub retry_config: Option<RetryConfig>,
    pub retry_body: Option<Vec<u8>>,
    pub retry_count: u32,
    pub script_enabled: bool,
    pub script_dir: String,
    pub request_counter: Option<crate::dns::choice::DynamicChoice>,
    pub chosen_backup: Option<String>,
}

impl InterceptContext {
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.response_headers.set(name, value);
    }
    /// 拦截器直接响应
    pub fn respond(&mut self, status: u16, body: &str) {
        self.response_status = Some(status);
        self.response_body = Some(body.as_bytes().to_vec());
    }
}

pub type RequestInterceptFn = Box<dyn Fn(&mut InterceptContext) -> InterceptOutcome + Send + Sync>;
pub type ResponseInterceptFn =
    Box<dyn Fn(&mut InterceptContext, &mut UpstreamHeads) -> Option<ResponseAppend> + Send + Sync>;

pub struct MatchedInterceptor {
    pub name: &'static str,
    pub priority: i32,
    pub request: Option<RequestInterceptFn>,
    pub response: Option<ResponseInterceptFn>,
}

// ------------------------------------------------------------------ 构建拦截器列表

/// 对应 options.js 的 createIntercepts
pub fn create_intercepts(
    intercepts: &DomainMap,
    context: &mut InterceptContext,
    script_enabled: bool,
) -> Vec<MatchedInterceptor> {
    let hostname = context.r_options.hostname.clone();
    let path = context.r_options.path.clone();

    let Some(opts) = crate::matcher::match_hostname_all(intercepts, &hostname, "get interceptOpts")
    else {
        return Vec::new();
    };

    let hostname_matched: Captures = opts
        .get("matched")
        .and_then(|v| v.as_array())
        .map(|arr| {
            let mut c = Captures::default();
            c.list = arr
                .iter()
                .map(|v| v.as_str().unwrap_or_default().to_string())
                .collect();
            c
        })
        .unwrap_or_default();

    let mut result: Vec<MatchedInterceptor> = Vec::new();

    if let Value::Object(map) = &opts {
        for (regexp, intercept_opt) in map {
            if regexp == "matched" {
                continue;
            }
            let Some(matched) = is_matched(&path, regexp) else {
                continue;
            };
            if let Some(exclusions) = intercept_opt.get("exclusions") {
                if is_excluded(&path, exclusions) {
                    continue;
                }
            }

            for def in all_defs() {
                if !def.is(intercept_opt) {
                    continue;
                }
                let mi = def.build(
                    intercept_opt.clone(),
                    matched.clone(),
                    hostname_matched.clone(),
                );
                if result.iter().any(|x| x.name == mi.name) {
                    continue;
                }
                result.push(mi);
            }
        }
    }

    result.sort_by_key(|x| x.priority);

    // 脚本中间件：始终作为第一个请求拦截器
    if script_enabled {
        let mut all = vec![insert_script_middleware()];
        all.extend(result);
        return all;
    }
    result
}

fn is_excluded(path: &str, exclusions: &Value) -> bool {
    let list: Vec<String> = match exclusions {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Value::Object(map) => map.keys().cloned().collect(),
        _ => return false,
    };
    list.iter().any(|ex| is_matched(path, ex).is_some())
}

// ------------------------------------------------------------------ 工具函数

const REMOVE: &str = "[remove]";

fn get_max_age(opt: &Value) -> Option<u64> {
    let f =
        |key: &str| -> Option<f64> { opt.get(key).and_then(|v| v.as_f64()).filter(|v| *v > 0.0) };
    if let Some(v) = f("cacheSeconds")
        .or_else(|| f("cacheMaxAge"))
        .or_else(|| f("cache"))
    {
        return Some(v as u64);
    }
    if let Some(v) = f("cacheMinutes") {
        return Some((v * 60.0) as u64);
    }
    if let Some(v) = f("cacheHours") {
        return Some((v * 3600.0) as u64);
    }
    if let Some(v) = f("cacheDays") {
        return Some((v * 86400.0) as u64);
    }
    if let Some(v) = f("cacheWeeks") {
        return Some((v * 604800.0) as u64);
    }
    if let Some(v) = f("cacheMonths") {
        return Some((v * 2592000.0) as u64);
    }
    if let Some(v) = f("cacheYears") {
        return Some((v * 31536000.0) as u64);
    }
    None
}

fn replace_placeholders(
    url: &str,
    r_options: &RequestOptions,
    path_matched: &Captures,
    host_matched: &Captures,
) -> String {
    if !url.contains("${") {
        return url.to_string();
    }
    let mut out = url.replace("${host}", &r_options.hostname);

    if out.contains("${") {
        for prefix in ["p", "m"] {
            for (i, value) in path_matched.list.iter().enumerate() {
                out = out.replace(&format!("${{{}[{}]}}", prefix, i), value);
            }
        }
        for (i, value) in host_matched.list.iter().enumerate() {
            out = out.replace(&format!("${{h[{}]}}", i), value);
        }
        for (key, value) in &path_matched.groups {
            out = out.replace(&format!("${{{}}}", key), value);
        }
        for (key, value) in &host_matched.groups {
            out = out.replace(&format!("${{{}}}", key), value);
        }
    }
    if out.contains("${") {
        if let Ok(re) = Regex::new(r"\$\{[^}]+\}") {
            out = re.replace_all(&out, "").to_string();
        }
    }
    out
}

pub fn build_target_url(
    r_options: &RequestOptions,
    url_conf: &str,
    intercept_opt: &Value,
    matched: &Captures,
    hostname_matched: &Captures,
) -> String {
    let mut target = if let Some(replace) = intercept_opt.get("replace").and_then(|v| v.as_str()) {
        match Regex::new(replace) {
            Ok(re) => re.replace(&r_options.path, url_conf).to_string(),
            Err(_) => url_conf.to_string(),
        }
    } else if url_conf.starts_with("http:") || url_conf.starts_with("https:") {
        url_conf.to_string()
    } else {
        let uri = if r_options.path.starts_with("http:") || r_options.path.starts_with("https:") {
            let rest = &r_options.path[r_options.path.find("://").unwrap() + 3..];
            match rest.find('/') {
                Some(idx) => rest[idx..].to_string(),
                None => "/".to_string(),
            }
        } else {
            r_options.path.clone()
        };
        format!("{}{}", url_conf, uri)
    };

    target = replace_placeholders(&target, r_options, matched, hostname_matched);
    if target.starts_with("http:") || target.starts_with("https:") {
        target
    } else {
        format!("{}//{}", r_options.protocol, target)
    }
}

/// 应用代理目标：修改 r_options 指向新地址
fn do_proxy(r_options: &mut RequestOptions, proxy_target: &str) {
    let (protocol, rest) = match proxy_target.find("://") {
        Some(idx) => (&proxy_target[..idx], &proxy_target[idx + 3..]),
        None => ("http", proxy_target),
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port_opt) = split_host_port(authority);

    let original = Box::new(r_options.clone());
    r_options.original = Some(original);
    r_options.protocol = format!("{}:", protocol);
    r_options.hostname = host.clone();
    r_options.path = path;
    r_options.port = port_opt.unwrap_or(if protocol == "https" { 443 } else { 80 });
    r_options.set_header("host", &host_with_port(&host, r_options.port, protocol));
    if let Some(sni) = r_options.servername.clone() {
        let _ = sni;
    }
}

fn host_with_port(host: &str, port: u16, protocol: &str) -> String {
    let default_port = if protocol == "https" { 443 } else { 80 };
    if port == default_port {
        host.to_string()
    } else {
        format!("{}:{}", host, port)
    }
}

fn bool_value(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0) > 0.0,
        _ => false,
    }
}

fn is_true(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

fn cors_headers(ctx: &InterceptContext) -> Vec<(String, String)> {
    let origin = ctx.r_options.header("origin").unwrap_or("").to_string();
    if origin.is_empty() {
        Vec::new()
    } else {
        vec![
            (
                "Access-Control-Allow-Credentials".to_string(),
                "true".to_string(),
            ),
            ("Access-Control-Allow-Origin".to_string(), origin),
        ]
    }
}

fn utc_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn reason_of(status: u16) -> &'static str {
    crate::proxy::http::status_reason(status)
}

/// 直接返回内容的通用处理（success / abort）
fn respond_with(
    ctx: &mut InterceptContext,
    kind: &str,
    default_status: u16,
    response_conf: &Value,
) {
    if bool_value(Some(response_conf)) && matches!(response_conf, Value::Bool(_)) {
        let mut body = format!(
            "DevSidecar {}: Request {}.\n\n  This request is matched by {} intercept.\n\n",
            default_status,
            if default_status == 403 {
                "abort"
            } else {
                "success"
            },
            kind
        );
        if default_status == 403 {
            body.push_str("  因配置abort拦截器，本请求直接返回403禁止访问。");
        } else {
            body.push_str("  因配置success拦截器，本请求直接返回200成功。");
        }
        ctx.set_header("Content-Type", "text/plain; charset=utf-8");
        ctx.set_header("DS-Interceptor", kind);
        for (k, v) in cors_headers(ctx) {
            ctx.set_header(&k, &v);
        }
        ctx.respond(default_status, &body);
        return;
    }

    let status = response_conf
        .get("status")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_status as u64) as u16;

    let body_val = ["html", "json", "script", "css", "text", "body"]
        .iter()
        .find_map(|k| response_conf.get(*k))
        .cloned();

    let body = match &body_val {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => format!(
            "DevSidecar {}: Request {}.\n\n  This request is matched by {} intercept.\n\n  因配置{}拦截器，本请求直接返回{}成功。",
            status,
            if default_status == 403 { "abort" } else { "success" },
            kind,
            kind,
            status
        ),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(Value::Object(map)) = response_conf.get("headers") {
        for (k, v) in map {
            headers.push((k.clone(), v.as_str().unwrap_or_default().to_string()));
        }
    }
    ctx.set_header("DS-Interceptor", kind);

    if status != 204 {
        let content_type = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.clone());
        let content_type = match content_type {
            Some(ct) => ct,
            None => {
                let guess = if response_conf.get("html").is_some() {
                    "text/html"
                } else if response_conf.get("json").is_some() {
                    "application/json"
                } else if response_conf.get("script").is_some() {
                    "application/javascript"
                } else if response_conf.get("css").is_some() {
                    "text/css"
                } else {
                    "text/plain"
                };
                guess.to_string()
            }
        };
        let content_type = if content_type.contains("charset") {
            content_type
        } else {
            format!("{}; charset=utf-8", content_type)
        };
        ctx.set_header("Content-Type", &content_type);
    }
    for (k, v) in headers {
        if k.to_lowercase() == "content-type" {
            continue;
        }
        ctx.set_header(&k, &v);
    }
    if ctx.r_options.header("origin").is_some()
        && ctx
            .response_headers
            .get("Access-Control-Allow-Origin")
            .is_none()
    {
        for (k, v) in cors_headers(ctx) {
            ctx.set_header(&k, &v);
        }
    }
    ctx.respond(status, &body);
}

// ------------------------------------------------------------------ 各拦截器实现

fn insert_script_middleware() -> MatchedInterceptor {
    MatchedInterceptor {
        name: "insertScript",
        priority: 99,
        request: Some(Box::new(|ctx| {
            let prefix = "/____ds_script____/";
            if !ctx.r_options.path.starts_with(prefix) {
                return InterceptOutcome::Continue;
            }
            let mut filename = ctx.r_options.path[prefix.len()..].to_string();
            if filename == "global" {
                filename = "tampermonkey".to_string();
            }
            let scripts = monkey_scripts(&ctx.script_dir);
            match scripts.get(&filename) {
                Some(script) => {
                    ctx.set_header("DS-Middleware", "ds_script");
                    ctx.set_header("Content-Type", "application/javascript; charset=utf-8");
                    ctx.set_header("Cache-Control", "public, max-age=86401, immutable");
                    ctx.set_header("Last-Modified", &utc_now());
                    ctx.set_header("Date", &utc_now());
                    ctx.respond(200, script);
                    InterceptOutcome::Handled
                }
                None => {
                    ctx.set_header("DS-Middleware", "ds_script");
                    ctx.set_header("Content-Type", "text/plain; charset=utf-8");
                    ctx.respond(404, &format!("DevSidecar: script '{}' not found", filename));
                    InterceptOutcome::Handled
                }
            }
        })),
        response: None,
    }
}

/// 内置脚本（油猴等）缓存
fn monkey_scripts(dir: &str) -> HashMap<String, String> {
    static CACHE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    {
        if !cache.read().is_empty() {
            return cache.read().clone();
        }
    }
    let files = [
        "github.script",
        "google.js",
        "tampermonkey.script",
        "tampermonkey.js",
    ];
    let mut map = HashMap::new();
    for file in files {
        let path = std::path::Path::new(dir).join(file);
        if let Ok(content) = std::fs::read_to_string(&path) {
            let key = file.replace(".script", "").replace(".js", "");
            map.insert(key, content);
        }
    }
    *cache.write() = map.clone();
    map
}

/// name / priority 仅为声明处的可读性说明，实际生效值由各 build_* 函数返回的 MatchedInterceptor 决定
#[allow(dead_code)]
struct Def {
    name: &'static str,
    priority: i32,
    is: fn(&Value) -> bool,
    build: fn(Value, Captures, Captures) -> MatchedInterceptor,
}

impl Def {
    fn build(&self, opt: Value, matched: Captures, host_matched: Captures) -> MatchedInterceptor {
        (self.build)(opt, matched, host_matched)
    }
    fn is(&self, opt: &Value) -> bool {
        (self.is)(opt)
    }
}

fn all_defs() -> Vec<Def> {
    vec![
        Def {
            name: "retry",
            priority: 100,
            is: |o| o.get("retry").is_some() && !o.get("retry").unwrap().is_null(),
            build: build_retry,
        },
        Def {
            name: "options",
            priority: 101,
            is: |o| o.get("options").map(|v| !v.is_null()).unwrap_or(false),
            build: build_options,
        },
        Def {
            name: "success",
            priority: 102,
            is: |o| o.get("success").map(|v| !v.is_null()).unwrap_or(false),
            build: build_success,
        },
        Def {
            name: "abort",
            priority: 103,
            is: |o| o.get("abort").map(|v| !v.is_null()).unwrap_or(false),
            build: build_abort,
        },
        Def {
            name: "cacheRequest",
            priority: 104,
            is: |o| get_max_age(o).is_some(),
            build: build_cache_request,
        },
        Def {
            name: "redirect",
            priority: 105,
            is: |o| o.get("redirect").map(|v| !v.is_null()).unwrap_or(false),
            build: build_redirect,
        },
        Def {
            name: "requestReplace",
            priority: 111,
            is: |o| o.get("requestReplace").is_some(),
            build: build_request_replace,
        },
        Def {
            name: "proxy",
            priority: 121,
            is: |o| o.get("proxy").map(|v| !v.is_null()).unwrap_or(false),
            build: build_proxy,
        },
        Def {
            name: "sni",
            priority: 123,
            is: |o| {
                o.get("sni").is_some()
                    && !o.get("sni").unwrap().is_null()
                    && o.get("proxy").map(|v| v.is_null()).unwrap_or(true)
            },
            build: build_sni,
        },
        Def {
            name: "unVerifySsl",
            priority: 124,
            is: |o| {
                is_true(o.get("unVerifySsl")) || matches!(o.get("ssl"), Some(Value::Bool(false)))
            },
            build: build_unverify_ssl,
        },
        Def {
            name: "AfterOPTIONSHeaders",
            priority: 201,
            is: |o| o.get("options").map(|v| !v.is_null()).unwrap_or(false),
            build: build_after_options,
        },
        Def {
            name: "cacheResponse",
            priority: 202,
            is: |o| get_max_age(o).is_some(),
            build: build_cache_response,
        },
        Def {
            name: "responseReplace",
            priority: 203,
            is: |o| o.get("responseReplace").is_some(),
            build: build_response_replace,
        },
        Def {
            name: "script",
            priority: 211,
            is: |o| o.get("script").map(|v| !v.is_null()).unwrap_or(false),
            build: build_script,
        },
    ]
}

// ---------------- retry

fn build_retry(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "retry",
        priority: 100,
        request: Some(Box::new(move |ctx| {
            let cfg = normalize_retry(opt.get("retry"));
            if let Some(cfg) = cfg {
                if cfg.times > 0 {
                    ctx.retry_config = Some(cfg);
                } else {
                    log_warn!("retry 配置无效（次数需 > 0）: {}", ctx.r_options.hostname);
                }
            }
            InterceptOutcome::Continue
        })),
        response: None,
    }
}

fn normalize_retry(retry: Option<&Value>) -> Option<RetryConfig> {
    match retry {
        Some(Value::Number(n)) => {
            let times = n.as_f64().unwrap_or(0.0).floor().max(0.0) as u32;
            Some(RetryConfig {
                times,
                statuses: vec![500],
                methods: default_retry_methods(),
            })
        }
        Some(Value::Object(map)) => {
            let statuses: Vec<u16> = map
                .get("statuses")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u16))
                        .collect()
                })
                .unwrap_or_else(|| vec![500]);
            let statuses = if statuses.is_empty() {
                vec![500]
            } else {
                statuses
            };
            let times = map
                .get("times")
                .or_else(|| map.get("retries"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .floor()
                .max(0.0) as u32;
            let methods: Vec<String> = map
                .get("methods")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_uppercase()))
                        .collect()
                })
                .unwrap_or_else(default_retry_methods);
            let methods = if methods.is_empty() {
                default_retry_methods()
            } else {
                methods
            };
            Some(RetryConfig {
                times,
                statuses,
                methods,
            })
        }
        _ => None,
    }
}

// ---------------- OPTIONS

fn build_options(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "options",
        priority: 101,
        request: Some(Box::new(move |ctx| {
            if ctx.r_options.method != "OPTIONS" || ctx.r_options.header("origin").is_none() {
                return InterceptOutcome::Continue;
            }
            let allow_headers = ctx
                .r_options
                .header("access-control-request-headers")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    opt.get("optionsAllowHeaders")
                        .map(|v| match v {
                            Value::Array(arr) => arr
                                .iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(","),
                            other => other.as_str().unwrap_or("*").to_string(),
                        })
                        .unwrap_or_else(|| "*".to_string())
                });
            let allow_methods = ctx
                .r_options
                .header("access-control-request-method")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    opt.get("optionsAllowMethods")
                        .map(|v| match v {
                            Value::Array(arr) => arr
                                .iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(","),
                            other => other.as_str().unwrap_or("").to_string(),
                        })
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "GET,POST,PUT,DELETE,HEAD,OPTIONS,PATCH".to_string())
                });
            let origin = ctx.r_options.header("origin").unwrap_or("").to_string();

            ctx.set_header("DS-Interceptor", "options");
            ctx.set_header("Access-Control-Allow-Origin", &origin);
            ctx.set_header("Access-Control-Allow-Headers", &allow_headers);
            ctx.set_header("Access-Control-Allow-Methods", &allow_methods);
            let max_age = opt
                .get("optionsMaxAge")
                .and_then(|v| v.as_u64())
                .unwrap_or(2592000);
            ctx.set_header("Access-Control-Max-Age", &max_age.to_string());
            ctx.set_header("Date", &utc_now());
            ctx.set_header("Vary", "Origin");
            if !matches!(opt.get("optionsCredentials"), Some(Value::Bool(false)))
                && opt.get("optionsCredentials").and_then(|v| v.as_str()) != Some("false")
            {
                ctx.set_header("Access-Control-Allow-Credentials", "true");
            }
            ctx.response_status = Some(200);
            ctx.response_body = Some(Vec::new());
            InterceptOutcome::Handled
        })),
        response: None,
    }
}

// ---------------- success / abort

fn build_success(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "success",
        priority: 102,
        request: Some(Box::new(move |ctx| {
            let conf = opt.get("success").cloned().unwrap_or(Value::Bool(true));
            if is_true(Some(&conf)) {
                respond_with(ctx, "success", 200, &Value::Bool(true));
            } else {
                respond_with(ctx, "success", 200, &conf);
            }
            if let Some(max_age) = get_max_age(&opt) {
                ctx.set_header(
                    "Cache-Control",
                    &format!("public, max-age={}, immutable", max_age + 1),
                );
            }
            InterceptOutcome::Handled
        })),
        response: None,
    }
}

fn build_abort(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "abort",
        priority: 103,
        request: Some(Box::new(move |ctx| {
            let conf = opt.get("abort").cloned().unwrap_or(Value::Bool(true));
            if is_true(Some(&conf)) {
                respond_with(ctx, "abort", 403, &Value::Bool(true));
            } else {
                respond_with(ctx, "abort", 403, &conf);
            }
            InterceptOutcome::Handled
        })),
        response: None,
    }
}

// ---------------- cacheRequest

fn build_cache_request(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "cacheRequest",
        priority: 104,
        request: Some(Box::new(move |ctx| {
            if ctx.r_options.method != "GET" {
                return InterceptOutcome::Continue;
            }
            let cache_control = ctx
                .r_options
                .header("cache-control")
                .unwrap_or("")
                .to_lowercase();
            if cache_control.contains("no-cache") || cache_control.contains("no-store") {
                return InterceptOutcome::Continue;
            }
            let pragma = ctx.r_options.header("pragma").unwrap_or("").to_lowercase();
            if pragma.contains("no-cache") || pragma.contains("no-store") {
                return InterceptOutcome::Continue;
            }
            let last_modified = match parse_if_modified_since(
                ctx.r_options.header("if-modified-since").unwrap_or(""),
            ) {
                Some(v) => v,
                None => return InterceptOutcome::Continue,
            };
            let Some(max_age) = get_max_age(&opt) else {
                return InterceptOutcome::Continue;
            };
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            if now_ms - last_modified > (max_age as i64) * 1000 {
                return InterceptOutcome::Continue;
            }
            ctx.set_header("DS-Interceptor", &format!("cache: {}", max_age));
            ctx.response_status = Some(304);
            ctx.response_body = Some(Vec::new());
            log_info!(
                "cache intercept: {}",
                crate::util::diag::safe_url(&ctx.r_options.url())
            );
            InterceptOutcome::Handled
        })),
        response: None,
    }
}

fn parse_if_modified_since(value: &str) -> Option<i64> {
    if value.is_empty() {
        return None;
    }
    if let Ok(n) = value.trim().parse::<i64>() {
        return Some(n);
    }
    match chrono::DateTime::parse_from_rfc2822(value) {
        Ok(dt) => Some(dt.timestamp_millis()),
        Err(_) => {
            log_warn!("cache intercept: 解析 if-modified-since 失败: '{}'", value);
            None
        }
    }
}

// ---------------- redirect

fn build_redirect(opt: Value, m: Captures, h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "redirect",
        priority: 105,
        request: Some(Box::new(move |ctx| {
            let conf = opt
                .get("redirect")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let target = build_target_url(&ctx.r_options, &conf, &opt, &m, &h);
            ctx.set_header("Location", &target);
            ctx.set_header("DS-Interceptor", "redirect");
            for (k, v) in cors_headers(ctx) {
                ctx.set_header(&k, &v);
            }
            if let Some(max_age) = get_max_age(&opt) {
                ctx.set_header(
                    "Cache-Control",
                    &format!("public, max-age={}, immutable", max_age + 1),
                );
            }
            ctx.response_status = Some(302);
            ctx.response_body = Some(Vec::new());
            log_info!(
                "redirect intercept: {} ➜ {}",
                crate::util::diag::safe_url(&ctx.r_options.url()),
                crate::util::diag::safe_text(&target)
            );
            InterceptOutcome::Handled
        })),
        response: None,
    }
}

// ---------------- requestReplace

fn build_request_replace(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "requestReplace",
        priority: 111,
        request: Some(Box::new(move |ctx| {
            let Some(conf) = opt.get("requestReplace") else {
                return InterceptOutcome::Continue;
            };
            let mut actions = String::new();
            if let Some(Value::Object(map)) = conf.get("headers") {
                for (key, value) in map {
                    let value = value.as_str().unwrap_or("").to_string();
                    if value == REMOVE {
                        ctx.r_options.remove_header(key);
                    } else if !value.is_empty() {
                        ctx.r_options.set_header(key, &value);
                    }
                }
                actions.push_str("headers");
            }
            if bool_value(conf.get("doDownload")) && ctx.r_options.path.contains("DS_DOWNLOAD") {
                ctx.r_options.do_download = true;
                let path = ctx.r_options.path.clone();
                if let Ok(re) = Regex::new(r"[?&/]?DS_DOWNLOAD(=[^?&/]+)?$") {
                    ctx.r_options.path = re.replace(&path, "").to_string();
                }
                if !actions.is_empty() {
                    actions.push(',');
                }
                actions.push_str("path:remove-DS_DOWNLOAD");
            }
            ctx.set_header("DS-RequestReplace-Interceptor", &actions);
            InterceptOutcome::Continue
        })),
        response: None,
    }
}

// ---------------- proxy

fn build_proxy(opt: Value, m: Captures, h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "proxy",
        priority: 121,
        request: Some(Box::new(move |ctx| {
            let mut proxy_conf = opt
                .get("proxy")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(Value::Array(backup)) = opt.get("backup") {
                let backup_list: Vec<String> = backup
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if !backup_list.is_empty() {
                    let mut list = vec![proxy_conf.clone()];
                    list.extend(backup_list);
                    let key = format!("{}/proxy", ctx.r_options.hostname);
                    let choice = request_counter(&key, &list);
                    if let Some(value) = choice.value.clone() {
                        ctx.chosen_backup = Some(value.clone());
                        proxy_conf = value;
                    }
                    ctx.request_counter = Some(choice);
                }
            }

            let origin = ctx.r_options.hostname.clone();
            let target = build_target_url(&ctx.r_options, &proxy_conf, &opt, &m, &h);
            do_proxy(&mut ctx.r_options, &target);

            let mut header = format!("proxy: {}", target);
            if let Some(sni) = opt.get("sni").and_then(|v| v.as_str()) {
                ctx.r_options.servername = Some(sni.to_string());
                ctx.r_options.unverify_ssl = true;
                header.push_str(&format!(", sni: {}", sni));
            } else if is_true(opt.get("unVerifySsl")) {
                ctx.r_options.unverify_ssl = true;
                header.push_str(", unVerifySsl");
            }
            ctx.set_header("DS-Interceptor", &header);
            log_info!(
                "proxy intercept: hostname: {}, target: {}",
                origin,
                crate::util::diag::safe_text(&target)
            );
            InterceptOutcome::Continue
        })),
        response: None,
    }
}

/// 代理备选域名的优选计数器缓存
fn request_counter(key: &str, backup_list: &[String]) -> crate::dns::choice::DynamicChoice {
    static CACHE: OnceLock<RwLock<HashMap<String, crate::dns::choice::DynamicChoice>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    {
        let mut guard = cache.write();
        let entry = guard
            .entry(key.to_string())
            .or_insert_with(|| crate::dns::choice::DynamicChoice::new(key));
        if entry.backup_list.is_empty() && entry.value.is_none() {
            entry.set_backup_list(backup_list.to_vec());
        }
        let value = entry.value.clone();
        if let Some(v) = value {
            entry.do_count(&v, false);
        }
        entry.clone()
    }
}

// ---------------- sni

fn build_sni(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "sni",
        priority: 123,
        request: Some(Box::new(move |ctx| {
            let sni = opt
                .get("sni")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if sni.is_empty() {
                ctx.r_options.servername = Some(String::new());
                ctx.set_header("DS-Interceptor", "sni: (disabled)");
                log_info!("sni intercept: SNI 已禁用: {}", ctx.r_options.hostname);
                return InterceptOutcome::Continue;
            }
            ctx.r_options.servername = Some(sni.clone());
            ctx.r_options.unverify_ssl = true;
            ctx.set_header("DS-Interceptor", &format!("sni: {}, unVerifySsl", sni));
            log_info!(
                "sni intercept: sni replace servername: {} ➜ {}",
                ctx.r_options.hostname,
                sni
            );
            InterceptOutcome::Continue
        })),
        response: None,
    }
}

// ---------------- unVerifySsl

fn build_unverify_ssl(_opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "unVerifySsl",
        priority: 124,
        request: Some(Box::new(|ctx| {
            ctx.r_options.unverify_ssl = true;
            ctx.set_header("DS-Interceptor", "unVerifySsl");
            InterceptOutcome::Continue
        })),
        response: None,
    }
}

// ---------------- AfterOPTIONSHeaders

fn build_after_options(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "AfterOPTIONSHeaders",
        priority: 201,
        request: None,
        response: Some(Box::new(move |ctx, upstream| {
            if ctx.r_options.method == "OPTIONS" || ctx.r_options.header("origin").is_none() {
                return None;
            }
            let origin = ctx.r_options.header("origin").unwrap_or("").to_string();
            let mut vary = "Origin".to_string();
            if let Some(existing) = upstream.get("vary") {
                let existing = existing.to_string();
                if !existing.split(',').any(|x| x.trim() == "Origin") {
                    vary = format!("{}, Origin", existing);
                } else {
                    vary = existing;
                }
            }
            let policy = opt
                .get("optionsCrossPolicy")
                .and_then(|v| v.as_str())
                .unwrap_or("cross-origin");
            ctx.set_header("Access-Control-Allow-Credentials", "true");
            ctx.set_header("Access-Control-Allow-Origin", &origin);
            ctx.set_header("Cross-Origin-Resource-Policy", policy);
            ctx.set_header("Vary", &vary);
            ctx.set_header("DS-AfterOPTIONSHeaders-Interceptor", "1");
            None
        })),
    }
}

// ---------------- cacheResponse

fn build_cache_response(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "cacheResponse",
        priority: 202,
        request: None,
        response: Some(Box::new(move |ctx, upstream| {
            if ctx.r_options.method != "GET" {
                return None;
            }
            if let Some(Value::Object(list)) = opt.get("cacheExcludeStatusCodeList") {
                if list.contains_key(&upstream.status.to_string()) {
                    return None;
                }
            }
            let mut min_status = opt
                .get("cacheMinStatusCode")
                .and_then(|v| v.as_u64())
                .unwrap_or(200) as u16;
            let mut max_status = opt
                .get("cacheMaxStatusCode")
                .and_then(|v| v.as_u64())
                .unwrap_or(303) as u16;
            if min_status > max_status {
                std::mem::swap(&mut min_status, &mut max_status);
            }
            if upstream.status < min_status || upstream.status > max_status {
                return None;
            }
            let mut max_age = match get_max_age(&opt) {
                Some(v) => v,
                None => return None,
            };
            let immutable = !matches!(opt.get("cacheImmutable"), Some(Value::Bool(false)))
                && opt.get("cacheImmutable").and_then(|v| v.as_str()) != Some("false");
            let cache_type = opt
                .get("cacheControlType")
                .and_then(|v| v.as_str())
                .unwrap_or("public");

            if let Some(cc) = upstream.get("cache-control") {
                if let Ok(re) = Regex::new(r"(?i)max-age=(\d+)") {
                    if let Some(caps) = re.captures(cc) {
                        if let Ok(origin_max) = caps[1].parse::<u64>() {
                            if origin_max > max_age {
                                if immutable && !cc.contains("immutable") {
                                    max_age = origin_max;
                                } else {
                                    ctx.set_header(
                                        "DS-Cache-Response-Interceptor",
                                        &format!("skip: {} > {}", origin_max, max_age),
                                    );
                                    return None;
                                }
                            }
                        }
                    }
                }
            }

            let immutable_str = if immutable { ", immutable" } else { "" };
            let cache_control = format!("{}, max-age={}{}", cache_type, max_age + 1, immutable_str);
            let last_modified = utc_now();
            let expires = chrono::Utc::now() + chrono::Duration::seconds(max_age as i64);
            let expires = expires.format("%a, %d %b %Y %H:%M:%S GMT").to_string();

            if upstream.get("cache-control").is_some() {
                upstream.set("cache-control", &cache_control);
            } else {
                ctx.set_header("Cache-Control", &cache_control);
            }
            if upstream.get("last-modified").is_some() {
                upstream.set("last-modified", &last_modified);
            } else {
                ctx.set_header("Last-Modified", &last_modified);
            }
            if upstream.get("expires").is_some() {
                upstream.set("expires", &expires);
            } else {
                ctx.set_header("Expires", &expires);
            }
            ctx.set_header("DS-Cache-Response-Interceptor", &max_age.to_string());
            None
        })),
    }
}

// ---------------- responseReplace

fn build_response_replace(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "responseReplace",
        priority: 203,
        request: None,
        response: Some(Box::new(move |ctx, upstream| {
            if upstream.status != 200 {
                return None;
            }
            let Some(conf) = opt.get("responseReplace") else {
                return None;
            };
            let mut headers: Vec<(String, String)> = Vec::new();
            if let Some(Value::Object(map)) = conf.get("headers") {
                for (k, v) in map {
                    headers.push((k.to_lowercase(), v.as_str().unwrap_or("").to_string()));
                }
            }

            let mut actions = String::new();
            if bool_value(conf.get("doDownload")) || ctx.r_options.do_download {
                let filename = ctx
                    .r_options
                    .path
                    .rsplit('/')
                    .find(|s| !s.is_empty())
                    .unwrap_or("UNKNOWN_FILENAME")
                    .to_string();
                headers.push((
                    "content-disposition".to_string(),
                    format!("attachment; filename=\"{}\"", filename),
                ));
                if !headers.iter().any(|(k, _)| k == "content-type") {
                    headers.push((
                        "content-type".to_string(),
                        "application/octet-stream".to_string(),
                    ));
                }
                if get_max_age(&opt).unwrap_or(0) == 0 {
                    headers.push(("cache-control".to_string(), REMOVE.to_string()));
                    headers.push(("last-modified".to_string(), REMOVE.to_string()));
                    headers.push(("expires".to_string(), REMOVE.to_string()));
                }
                actions.push_str(&format!("download:{}", filename));
            }

            if replace_response_headers(&headers, ctx, upstream) {
                if !actions.is_empty() {
                    actions.push(',');
                }
                actions.push_str("headers");
            }
            if !actions.is_empty() {
                ctx.set_header("DS-ResponseReplace-Interceptor", &actions);
            }
            None
        })),
    }
}

fn replace_response_headers(
    new_headers: &[(String, String)],
    ctx: &mut InterceptContext,
    upstream: &mut UpstreamHeads,
) -> bool {
    if new_headers.is_empty() {
        return false;
    }
    let mut changed = false;
    for (key, value) in new_headers {
        if let Some(old) = upstream.get(key) {
            let old = old.to_string();
            if old != *value {
                if value == REMOVE {
                    upstream.remove(key);
                } else {
                    upstream.set(key, value);
                }
                changed = true;
            }
        } else if value != REMOVE && !value.is_empty() {
            ctx.set_header(key, value);
            changed = true;
        }
    }
    changed
}

// ---------------- script

fn build_script(opt: Value, _m: Captures, _h: Captures) -> MatchedInterceptor {
    MatchedInterceptor {
        name: "script",
        priority: 211,
        request: None,
        response: Some(Box::new(move |ctx, upstream| {
            if ctx.r_options.hostname == "github.com"
                && ctx.r_options.header("turbo-frame") == Some("repo-content-turbo-frame")
            {
                return None;
            }
            let content_type = upstream.get("content-type").unwrap_or("").to_string();
            if !content_type.contains("text/html") {
                ctx.set_header("DS-Script-Interceptor", "Not text/html");
                return None;
            }

            let keys: Vec<String> = match opt.get("script") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
                _ => return None,
            };

            let nonce = nonce_attr(upstream);
            let mut tags = String::new();
            for key in &keys {
                if key == "global" || key == "tampermonkey" {
                    continue;
                }
                if key.contains('/') {
                    tags.push_str(&format!("\r\n\t{}", script_tag_src(key, &nonce)));
                } else {
                    let scripts = monkey_scripts(&ctx.script_dir);
                    if !scripts.contains_key(key) {
                        continue;
                    }
                    tags.push_str(&format!(
                        "\r\n\t{}",
                        script_tag_src(&format!("/____ds_script____/{}", key), &nonce)
                    ));
                }
            }
            if tags.is_empty() {
                return None;
            }

            match opt.get("tampermonkeyScript").and_then(|v| v.as_str()) {
                Some(url) => {
                    tags = format!("\r\n\t{}{}", script_tag_src(url, &nonce), tags);
                }
                None => {
                    tags = format!(
                        "\r\n\t{}{}",
                        script_tag_src("/____ds_script____/tampermonkey", &nonce),
                        tags
                    );
                }
            }

            if ctx.r_options.hostname == "github.com" {
                tags.push_str(&format!(
                    "\r\n\t{}",
                    script_tag_src("https://github.githubassets.com/assets/fakefile.js", &nonce)
                ));
            }

            ctx.set_header("DS-Script-Interceptor", "true");
            Some(ResponseAppend {
                head: format!("{}\r\n", tags),
                body: String::new(),
                stop: false,
            })
        })),
    }
}

fn script_tag_src(src: &str, nonce: &str) -> String {
    format!(
        "<script crossorigin=\"anonymous\" defer=\"defer\" type=\"application/javascript\" src=\"{}\"{}></script>",
        src, nonce
    )
}

fn nonce_attr(upstream: &UpstreamHeads) -> String {
    let csp = upstream
        .get("content-security-policy")
        .or_else(|| upstream.get("content-security-policy-report-only"))
        .unwrap_or("")
        .to_string();
    if csp.is_empty() {
        return String::new();
    }
    match Regex::new(r#"['"]nonce-([^'"]+)['"]"#) {
        Ok(re) => match re.captures(&csp) {
            Some(c) => format!(" nonce=\"{}\"", &c[1]),
            None => {
                log_warn!("getNonce: CSP 存在但未匹配到 nonce");
                String::new()
            }
        },
        Err(_) => String::new(),
    }
}

/// 处理拦截配置中的 script 地址，自动生成伪脚本地址的代理配置
pub fn handle_script_intercept_config(intercepts: &mut Value) {
    let script_proxy_pre = "/____ds_script_proxy____/";
    let Some(hosts) = intercepts.as_object_mut() else {
        return;
    };

    let mut additions: Vec<(String, Value)> = Vec::new();

    for (host_pattern, host_config) in hosts.iter_mut() {
        let Some(paths) = host_config.as_object_mut() else {
            continue;
        };

        let mut script_proxy: Vec<(String, String)> = Vec::new();

        for (_path_pattern, path_config) in paths.iter_mut() {
            let mut handle = |script_url: &str| -> Option<String> {
                if script_url.starts_with("https:") || script_url.starts_with("http:") {
                    let key = format!(
                        "{}{}.js",
                        script_proxy_pre,
                        script_url
                            .replace(".js", "")
                            .replace(|c: char| !c.is_alphanumeric(), "_")
                    );
                    script_proxy.push((key.clone(), script_url.to_string()));
                    Some(key)
                } else if script_url.starts_with('/') {
                    script_proxy.push((script_url.to_string(), script_url.to_string()));
                    None
                } else {
                    None
                }
            };

            let script_val = path_config.get("script").cloned();
            match script_val {
                Some(Value::Array(arr)) => {
                    let mut new_arr = Vec::new();
                    for item in arr {
                        let url = item.as_str().unwrap_or("").to_string();
                        match handle(&url) {
                            Some(key) => new_arr.push(Value::String(key)),
                            None => new_arr.push(Value::String(url)),
                        }
                    }
                    path_config["script"] = Value::Array(new_arr);
                }
                Some(Value::String(url)) => {
                    if let Some(key) = handle(&url) {
                        path_config["script"] = Value::String(key);
                    }
                }
                _ => {}
            }
            if let Some(Value::String(url)) = path_config.get("tampermonkeyScript").cloned() {
                if let Some(key) = handle(&url) {
                    path_config["tampermonkeyScript"] = Value::String(key);
                }
            }
        }

        for (key, url) in script_proxy {
            if key.starts_with(script_proxy_pre) {
                let pattern = format!("^{}$", key.replace('.', "\\."));
                if paths.contains_key(&pattern) {
                    continue;
                }
                additions.push((
                    host_pattern.clone(),
                    serde_json::json!({
                        pattern: {
                            "proxy": url,
                            "requestReplace": {
                                "headers": { "host": REMOVE, "referer": REMOVE, "cookie": REMOVE }
                            },
                            "responseReplace": {
                                "headers": {
                                    "content-type": "application/javascript; charset=utf-8",
                                    "set-cookie": REMOVE,
                                    "server": REMOVE
                                }
                            },
                            "cacheDays": 7,
                            "desc": "为伪脚本文件设置代理地址，并设置响应头 content-type，同时缓存7天。"
                        }
                    }),
                ));
            } else {
                if paths.contains_key(&key) {
                    continue;
                }
                additions.push((
                    host_pattern.clone(),
                    serde_json::json!({
                        key: {
                            "responseReplace": {
                                "headers": { "content-type": "application/javascript; charset=utf-8" }
                            },
                            "cacheDays": 7,
                            "desc": "为脚本设置响应头 content-type，同时缓存7天。"
                        }
                    }),
                ));
            }
        }
    }

    for (host_pattern, addition) in additions {
        if let Some(Value::Object(target)) = intercepts.get_mut(&host_pattern) {
            if let Some(add) = addition.as_object() {
                for (k, v) in add {
                    if !target.contains_key(k) {
                        target.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
}

/// 判断 target 是否 IP
pub fn target_is_ip(hostname: &str) -> bool {
    is_ip(hostname)
}

pub fn interceptor_reason(status: u16) -> &'static str {
    reason_of(status)
}

pub type SharedDomainMap = Arc<DomainMap>;
