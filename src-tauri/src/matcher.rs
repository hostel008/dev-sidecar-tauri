//! 域名 / 路径匹配工具（对应原版 `mitmproxy/src/utils/util.match.js`）

use parking_lot::RwLock;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

fn regex_cache() -> &'static RwLock<HashMap<String, Option<Regex>>> {
    static CACHE: OnceLock<RwLock<HashMap<String, Option<Regex>>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn compile_url_regexp(regexp: &str) -> Option<Regex> {
    let cache = regex_cache();
    if let Some(c) = cache.read().get(regexp) {
        return c.clone();
    }
    let mut pattern = regexp.to_string();
    let first = pattern.chars().next();
    if matches!(first, Some('*') | Some('?') | Some('+')) {
        pattern = format!(".{}", pattern);
    }
    let compiled = Regex::new(&pattern).ok();
    cache.write().insert(regexp.to_string(), compiled.clone());
    compiled
}

/// 正则捕获结果：位置分组列表 + 命名分组
#[derive(Debug, Clone, Default)]
pub struct Captures {
    pub list: Vec<String>,
    pub groups: HashMap<String, String>,
}

/// 对应 js `isMatched`：未命中返回 None，命中返回 [完整匹配, 分组...]
pub fn is_matched(url: &str, regexp: &str) -> Option<Captures> {
    if regexp == ".*" || regexp == "*" || regexp == "true" {
        return Some(Captures {
            list: vec![url.to_string()],
            groups: HashMap::new(),
        });
    }
    match compile_url_regexp(regexp) {
        Some(re) => re.captures(url).map(|c| {
            let mut groups = HashMap::new();
            for name in re.capture_names().flatten() {
                if let Some(m) = c.name(name) {
                    groups.insert(name.to_string(), m.as_str().to_string());
                }
            }
            Captures {
                list: c
                    .iter()
                    .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                    .collect(),
                groups,
            }
        }),
        None => {
            log_error!("匹配串有问题: {}", regexp);
            None
        }
    }
}

/// 将域名通配串转成正则串
fn domain_regexply(target: &str) -> String {
    if target == ".*" || target == "*" || target == "true" {
        return "^.*$".to_string();
    }
    let mut out = String::from("^");
    for ch in target.chars() {
        match ch {
            '.' => out.push_str("\\."),
            '*' => out.push_str(".*"),
            other => out.push(other),
        }
    }
    out.push('$');
    out
}

/// 预编译后的 hostMap
pub struct DomainMap {
    /// 精确域名 / 前缀通配 Excel（`*hostname`、`*.hostname`）快速匹配表
    pub origin: HashMap<String, Value>,
    /// 正则（含 `*xxx*` 等形式）
    pub patterns: Vec<(Regex, String, Value)>,
}

impl DomainMap {
    pub fn empty() -> Self {
        DomainMap {
            origin: HashMap::new(),
            patterns: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.origin.is_empty() && self.patterns.is_empty()
    }
}

/// 对应 js `domainMapRegexply`
pub fn domain_map_regexply(host_map: Option<&Value>) -> DomainMap {
    let mut origin: HashMap<String, Value> = HashMap::new();
    let mut patterns: Vec<(Regex, String, Value)> = Vec::new();

    let Some(map) = host_map.and_then(|v| v.as_object()) else {
        return DomainMap { origin, patterns };
    };

    for (raw_domain, value) in map {
        let mut domain = raw_domain.clone();
        if domain.starts_with('.') {
            if map.contains_key(&format!("*{}", domain)) {
                continue;
            }
            domain = format!("*{}", domain);
        }

        if domain.contains('*') || domain.starts_with('^') {
            let reg_domain = if domain.starts_with('^') {
                domain.clone()
            } else {
                domain_regexply(&domain)
            };
            if let Ok(re) = Regex::new(&reg_domain) {
                patterns.push((re, domain.clone(), value.clone()));
            } else {
                log_error!("匹配串有问题: {}", domain);
            }
            // `*xxx` 形式同时加入快速匹配
            if domain.find('*') == Some(0) && domain.rfind('*') == Some(0) {
                origin.insert(domain.clone(), value.clone());
            }
        } else {
            origin.insert(domain, value.clone());
        }
    }

    DomainMap { origin, patterns }
}

/// 对应 js `matchHostname`：返回首个命中的配置
pub fn match_hostname<'a>(
    host_map: &'a DomainMap,
    hostname: &str,
    _action: &str,
) -> Option<&'a Value> {
    if host_map.is_empty() {
        return None;
    }

    if let Some(v) = host_map.origin.get(hostname) {
        return Some(v);
    }
    if let Some(v) = host_map.origin.get(&format!("*.{}", hostname)) {
        return Some(v);
    }
    if let Some(v) = host_map.origin.get(&format!("*{}", hostname)) {
        return Some(v);
    }
    for (re, key, value) in &host_map.patterns {
        if re.is_match(hostname) {
            let _ = key;
            return Some(value);
        }
    }
    None
}

/// 对应 js `matchHostnameAll`：合并所有命中项（优先级从低到高覆盖），并生成 `matched`
pub fn match_hostname_all(host_map: &DomainMap, hostname: &str, _action: &str) -> Option<Value> {
    if host_map.is_empty() {
        return None;
    }

    let mut values: Map<String, Value> = Map::new();
    let mut matched_value: Option<Value> = None;

    // 优先级 1：正则匹配
    for (re, key, value) in &host_map.patterns {
        if let Some(caps) = re.captures(hostname) {
            merge_into(&mut values, value);
            let list: Vec<String> = caps
                .iter()
                .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
                .collect();
            if list.len() > 1 {
                matched_value = match matched_value.take() {
                    Some(Value::Array(mut arr)) => {
                        let mut rest = list.clone();
                        if !rest.is_empty() {
                            rest.remove(0);
                        }
                        arr.extend(rest.into_iter().map(Value::String));
                        Some(Value::Array(arr))
                    }
                    _ => Some(Value::Array(list.into_iter().map(Value::String).collect())),
                };
            } else if matched_value.is_none() && !list.is_empty() {
                matched_value = Some(Value::Array(list.into_iter().map(Value::String).collect()));
            }
            let _ = key;
        }
    }

    // 优先级 2
    if let Some(v) = host_map.origin.get(&format!("*{}", hostname)) {
        merge_into(&mut values, v);
    }
    // 优先级 3
    if let Some(v) = host_map.origin.get(&format!("*.{}", hostname)) {
        merge_into(&mut values, v);
    }
    // 优先级 4（最高）
    if let Some(v) = host_map.origin.get(hostname) {
        merge_into(&mut values, v);
    }

    if values.is_empty() {
        return None;
    }
    if let Some(m) = matched_value {
        values.insert("matched".to_string(), m);
    }
    crate::util::delete_null_items(&mut Value::Object(values.clone()));
    Some(Value::Object(values))
}

fn merge_into(base: &mut Map<String, Value>, patch: &Value) {
    let mut b = Value::Object(base.clone());
    crate::util::merge(&mut b, patch);
    if let Value::Object(m) = b {
        *base = m;
    }
}

/// 判断整数 <= 0（用于 cache 配置）
pub fn positive(v: Option<f64>) -> bool {
    match v {
        Some(n) => n > 0.0,
        None => false,
    }
}
