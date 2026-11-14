//! 域名测速与 IP 优选（对应原版 lib/speed）

use crate::dns::{is_ip, DnsMap};
use futures_util::StreamExt as _;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// 测速并发度：DNS 解析与 TCP 测速均按此上限并发执行，
/// 避免「域名 × provider」规模下串行等待过久
const SPEED_TEST_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    pub hostname: String,
    /// DNS 服务名称
    pub name: String,
    pub ip: String,
    /// 连接耗时（毫秒）
    pub delay: u64,
    pub ok: bool,
}

impl SpeedTestResult {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hostname": self.hostname,
            "name": self.name,
            "ip": self.ip,
            "delay": self.delay,
            "ok": self.ok,
        })
    }
}

struct Inner {
    enabled: bool,
    interval: u64,
    hostname_list: Vec<String>,
    dns_providers: Vec<String>,
    /// 每个域名的最优 IP
    best: HashMap<String, SpeedTestResult>,
    /// 最近一次完整结果
    results: Vec<SpeedTestResult>,
    testing: bool,
}

pub struct SpeedTester {
    inner: Arc<RwLock<Inner>>,
    dns_map: Arc<DnsMap>,
}

impl SpeedTester {
    pub fn new(dns_map: Arc<DnsMap>, config: &serde_json::Value) -> Self {
        let speed_test = config
            .pointer("/server/dns/speedTest")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let hostname_list: Vec<String> = speed_test
            .get("hostnameList")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let dns_providers: Vec<String> = speed_test
            .get("dnsProviders")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let inner = Inner {
            enabled: speed_test
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            interval: speed_test
                .get("interval")
                .and_then(|v| v.as_u64())
                .unwrap_or(300_000),
            hostname_list,
            dns_providers,
            best: HashMap::new(),
            results: Vec::new(),
            testing: false,
        };
        SpeedTester {
            inner: Arc::new(RwLock::new(inner)),
            dns_map,
        }
    }

    pub fn reload(&self, config: &serde_json::Value) {
        let speed_test = config
            .pointer("/server/dns/speedTest")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        let hostname_list: Vec<String> = speed_test
            .get("hostnameList")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let dns_providers: Vec<String> = speed_test
            .get("dnsProviders")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mut inner = self.inner.write();
        inner.enabled = speed_test
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        inner.interval = speed_test
            .get("interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(300_000);
        inner.hostname_list = hostname_list;
        inner.dns_providers = dns_providers;
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.read().enabled
    }

    pub fn best_ip(&self, hostname: &str) -> Option<String> {
        self.inner
            .read()
            .best
            .get(hostname)
            .filter(|r| r.ok && is_ip(&r.ip))
            .map(|r| r.ip.clone())
    }

    pub fn best_ip_with_info(&self, hostname: &str) -> Option<(String, String)> {
        self.inner
            .read()
            .best
            .get(hostname)
            .filter(|r| r.ok && is_ip(&r.ip))
            .map(|r| (r.ip.clone(), r.name.clone()))
    }

    pub fn results(&self) -> Vec<SpeedTestResult> {
        self.inner.read().results.clone()
    }

    pub fn results_json(&self) -> serde_json::Value {
        let results = self.inner.read().results.clone();
        serde_json::Value::Array(results.iter().map(|r| r.to_json()).collect())
    }

    pub fn is_testing(&self) -> bool {
        self.inner.read().testing
    }

    /// 执行一次完整测速
    pub async fn run_once(&self) -> Vec<SpeedTestResult> {
        let (enabled, hostname_list, providers) = {
            let inner = self.inner.read();
            (
                inner.enabled,
                inner.hostname_list.clone(),
                inner.dns_providers.clone(),
            )
        };
        if !enabled || hostname_list.is_empty() {
            return Vec::new();
        }
        {
            let mut inner = self.inner.write();
            if inner.testing {
                return inner.results.clone();
            }
            inner.testing = true;
        }

        let names = if providers.is_empty() {
            self.dns_map.names()
        } else {
            providers.clone()
        };

        // 阶段 1：并发解析各「域名 × provider」的 IP 候选
        let lookups: Vec<(String, String)> = hostname_list
            .iter()
            .flat_map(|h| names.iter().map(move |n| (h.clone(), n.clone())))
            .collect();
        let dns_map = self.dns_map.clone();
        let candidates: Vec<(String, String, String)> = futures_util::stream::iter(lookups)
            .map(|(hostname, name)| {
                let dns_map = dns_map.clone();
                async move {
                    let dns = dns_map.get(&name)?;
                    if dns.dns_name == "PreSet" || dns.dns_name == "ForSNI" {
                        return None;
                    }
                    let ip = dns.lookup(&hostname, 4, None).await?;
                    if is_ip(&ip) {
                        Some((hostname, dns.dns_name.clone(), ip))
                    } else {
                        None
                    }
                }
            })
            .buffer_unordered(SPEED_TEST_CONCURRENCY)
            .filter_map(|item| async move { item })
            .collect()
            .await;

        // 阶段 2：并发 TCP 测速（有界并发，避免瞬时大量连接）
        let results: Vec<SpeedTestResult> = futures_util::stream::iter(candidates)
            .map(|(hostname, name, ip)| async move {
                let delay = tcp_ping(&ip, 443, Duration::from_millis(3000)).await;
                SpeedTestResult {
                    hostname,
                    name,
                    ip,
                    delay: delay.unwrap_or(u64::MAX),
                    ok: delay.is_some(),
                }
            })
            .buffer_unordered(SPEED_TEST_CONCURRENCY)
            .collect()
            .await;

        // 阶段 3：按域名分组选优（输出顺序保持 hostname_list 顺序）
        let mut by_host: HashMap<String, Vec<SpeedTestResult>> = HashMap::new();
        for r in results {
            by_host.entry(r.hostname.clone()).or_default().push(r);
        }
        let mut all: Vec<SpeedTestResult> = Vec::new();
        for hostname in &hostname_list {
            if let Some(group) = by_host.get_mut(hostname) {
                group.sort_by_key(|r| r.delay);
                if let Some(best) = group.first() {
                    if best.ok {
                        log_info!(
                            "测速结果: {} ➜ {} (来自 {}，{} ms)",
                            hostname,
                            best.ip,
                            best.name,
                            best.delay
                        );
                        self.inner
                            .write()
                            .best
                            .insert(hostname.clone(), best.clone());
                    }
                }
                all.extend(group.iter().cloned());
            }
        }

        let mut inner = self.inner.write();
        inner.results = all.clone();
        inner.testing = false;
        all
    }

    /// 后台定时测速
    pub fn start_background(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                let (enabled, interval) = {
                    let inner = self.inner.read();
                    (inner.enabled, inner.interval)
                };
                if !enabled {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
                let results = self.run_once().await;
                crate::event::emit_speed(&results);
                tokio::time::sleep(Duration::from_millis(interval.max(10_000))).await;
            }
        });
    }
}

/// 通过 TCP 连接耗时近似测速
pub async fn tcp_ping(ip: &str, port: u16, timeout: Duration) -> Option<u64> {
    let start = std::time::Instant::now();
    let addr = format!("{}:{}", ip, port);
    let parsed: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr).await.ok()?.collect();
    let target = parsed.into_iter().next()?;
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target)).await {
        Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}

pub fn _unused(_: &HashMap<String, String>) {}
