pub mod choice;
pub mod wire;

use crate::dns::choice::DynamicChoice;
use crate::dns::wire::{answer_to_ip, encode_query, parse_response, TYPE_A, TYPE_AAAA};
use crate::matcher::{match_hostname, DomainMap};
use anyhow::Context;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};

// ---------------------------------------------------------------- 工具

pub fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

pub fn is_ipv6(ip: &str) -> bool {
    ip.parse::<std::net::Ipv6Addr>().is_ok()
}

pub fn zero_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_unspecified(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_unspecified(),
        Err(_) => false,
    }
}

fn ipv6_unavailable() -> bool {
    static UNAVAILABLE: OnceLock<bool> = OnceLock::new();
    *UNAVAILABLE.get_or_init(|| match std::net::UdpSocket::bind("[::]:0") {
        Ok(s) => s.connect("[2001:4860:4860::8888]:53").is_err(),
        Err(_) => true,
    })
}

static IPV6_ERR_COUNT: OnceLock<Mutex<u32>> = OnceLock::new();

pub fn report_ipv6_error(ip: &str) {
    if !is_ipv6(ip) || ipv6_unavailable() {
        return;
    }
    let counter = IPV6_ERR_COUNT.get_or_init(|| Mutex::new(0));
    let mut n = counter.lock();
    *n += 1;
    if *n >= 3 {
        log_warn!("IPv6 地址 {} 多次不可达，后续将忽略 IPv6 结果", ip);
    }
}

/// 累计 3 次以上错误时不再使用 IPv6
fn ipv6_disabled_runtime() -> bool {
    IPV6_ERR_COUNT
        .get_or_init(|| Mutex::new(0))
        .lock()
        .ge(&3u32)
}

// ---------------------------------------------------------------- 传输层

pub enum Transport {
    PreSet,
    Udp {
        server: String,
        port: u16,
    },
    Tcp {
        server: String,
        port: u16,
    },
    Https {
        url: String,
    },
    Tls {
        server: String,
        port: u16,
        servername: String,
        verify: bool,
    },
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("创建 http client 失败")
    })
}

/// 执行真实的 DNS 查询，返回 IP 列表
async fn do_query(
    transport: &Transport,
    hostname: &str,
    family: u8,
) -> anyhow::Result<Vec<String>> {
    let qtype = if family == 6 { TYPE_AAAA } else { TYPE_A };
    let id: u16 = rand::random();
    let packet = encode_query(id, hostname, qtype);

    let raw: Vec<u8> = match transport {
        Transport::PreSet => return Ok(Vec::new()),
        Transport::Udp { server, port } => {
            use tokio::net::UdpSocket;
            let bind_addr = if ipv6_unavailable() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind_addr).await?;
            let addr = format!("{}:{}", server, port);
            let parsed: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr).await?.collect();
            let target = parsed.into_iter().next().context("UDP DNS 地址解析失败")?;
            socket.send_to(&packet, target).await?;
            let mut buf = vec![0u8; 2048];
            let (len, _) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.recv_from(&mut buf),
            )
            .await
            .context("UDP DNS 查询超时")??;
            buf.truncate(len);
            buf
        }
        Transport::Tcp { server, port } => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let stream = tokio::net::TcpStream::connect((server.as_str(), *port)).await?;
            let mut stream = stream;
            let mut framed = Vec::with_capacity(packet.len() + 2);
            framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            framed.extend_from_slice(&packet);
            stream.write_all(&framed).await?;
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await?;
            let len = u16::from_be_bytes(head) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await?;
            body
        }
        Transport::Https { url } => {
            let resp = http_client()
                .post(url)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(packet)
                .send()
                .await?
                .error_for_status()?;
            resp.bytes().await?.to_vec()
        }
        Transport::Tls {
            server,
            port,
            servername,
            verify,
        } => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // DoH 客户端固定 HTTP/1.1（h2 对 DoH 无必要，保持行为稳定）
            let config = crate::tls::cached_client_config(*verify, true, false)?;
            let connector = tokio_rustls::TlsConnector::from(config);
            let tcp = tokio::net::TcpStream::connect((server.as_str(), *port)).await?;
            let name = rustls::pki_types::ServerName::try_from(servername.as_str())
                .map_err(|e| anyhow::anyhow!("非法 servername: {:?}", e))?
                .to_owned();
            let mut stream = connector.connect(name, tcp).await?;
            let mut framed = Vec::with_capacity(packet.len() + 2);
            framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            framed.extend_from_slice(&packet);
            stream.write_all(&framed).await?;
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await?;
            let len = u16::from_be_bytes(head) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await?;
            body
        }
    };

    let answers = parse_response(&raw)?;
    Ok(answers.iter().filter_map(answer_to_ip).collect())
}

// ---------------------------------------------------------------- BaseDNS

/// 查询结果的默认缓存时长（秒），可由 provider 配置的 `cacheTtl` 覆盖
const DEFAULT_DNS_CACHE_TTL_SECS: u64 = 60;

struct IpCache {
    choice: DynamicChoice,
    #[allow(dead_code)]
    lookup_count: u64,
    /// 缓存过期时刻（None 表示永不过期）
    expires_at: Option<std::time::Instant>,
}

impl IpCache {
    /// 判断缓存是否已在 `now` 时刻过期
    fn is_expired(&self, now: std::time::Instant) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
    }
}

pub struct BaseDns {
    pub dns_name: String,
    pub dns_type: String,
    pre_set_ip_list: Option<Arc<DomainMap>>,
    cache: Mutex<lru::LruCache<String, Arc<Mutex<IpCache>>>>,
    transport: Transport,
    /// 查询结果 TTL（None 表示不过期）
    ttl: Option<std::time::Duration>,
}

impl BaseDns {
    pub fn new(
        name: &str,
        type_name: &str,
        transport: Transport,
        pre_set_ip_list: Option<Arc<DomainMap>>,
        cache_ttl_secs: u64,
    ) -> Self {
        BaseDns {
            dns_name: name.to_string(),
            dns_type: type_name.to_string(),
            pre_set_ip_list,
            cache: Mutex::new(lru::LruCache::new(NonZeroUsize::new(1024).unwrap())),
            transport,
            ttl: if cache_ttl_secs == 0 {
                None
            } else {
                Some(std::time::Duration::from_secs(cache_ttl_secs))
            },
        }
    }

    /// 记录某 IP 的失败 / 成功
    pub fn count(&self, hostname: &str, ip: &str, is_error: bool) {
        if let Some(entry) = self.cache.lock().get(hostname) {
            entry.lock().choice.do_count(ip, is_error);
        }
    }

    pub fn is_preset(&self) -> bool {
        matches!(self.transport, Transport::PreSet)
    }

    pub async fn lookup(
        &self,
        hostname: &str,
        family: u8,
        ip_checker: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
    ) -> Option<String> {
        let existing = {
            let mut guard = self.cache.lock();
            guard.get(hostname).cloned()
        };

        // 缓存过期则丢弃，走下方重新解析流程
        let now = std::time::Instant::now();
        let existing = existing.filter(|entry| {
            let expired = entry.lock().is_expired(now);
            if expired {
                log_debug!(
                    "[DNS-over-{} '{}'] 缓存已过期，重新解析: {}",
                    self.dns_type,
                    self.dns_name,
                    hostname
                );
            }
            !expired
        });

        if let Some(entry) = existing {
            let cached_ip = {
                let mut e = entry.lock();
                let cached = e.choice.value.clone();
                if let Some(ip) = cached {
                    match ip_checker {
                        Some(checker) => {
                            if checker(&ip) {
                                e.choice.do_count(&ip, false);
                                log_info!(
                                    "[DNS-over-{} '{}'] 获取IP地址缓存: {} -> {}（测试通过）",
                                    self.dns_type,
                                    self.dns_name,
                                    hostname,
                                    ip
                                );
                                Some(ip)
                            } else {
                                log_info!("[DNS-over-{} '{}'] 获取IP地址缓存: {} -> {}（测试不通过）-> 回退域名", self.dns_type, self.dns_name, hostname, ip);
                                Some(hostname.to_string())
                            }
                        }
                        None => {
                            log_info!(
                                "[DNS-over-{} '{}'] 获取IP地址缓存: {} -> {}",
                                self.dns_type,
                                self.dns_name,
                                hostname,
                                ip
                            );
                            Some(ip)
                        }
                    }
                } else {
                    None
                }
            };
            if let Some(ip) = cached_ip {
                {
                    let mut e = entry.lock();
                    e.lookup_count += 1;
                }
                return Some(ip);
            }
        }

        let entry = Arc::new(Mutex::new(IpCache {
            choice: DynamicChoice::new(hostname),
            lookup_count: 0,
            expires_at: self.ttl.map(|ttl| std::time::Instant::now() + ttl),
        }));
        self.cache.lock().put(hostname.to_string(), entry.clone());
        log_info!(
            "[DNS-over-{} '{}'] 首次创建IP地址缓存区: {}",
            self.dns_type,
            self.dns_name,
            hostname
        );

        let start = std::time::Instant::now();
        let mut ip_list = self
            .lookup_with_preset(hostname, family)
            .await
            .unwrap_or_default();
        if ipv6_unavailable() || ipv6_disabled_runtime() {
            ip_list.retain(|ip| !is_ipv6(ip));
        }
        ip_list.push(hostname.to_string());

        {
            let mut e = entry.lock();
            e.choice.set_backup_list(ip_list.clone());
            e.lookup_count += 1;
        }

        let ip = entry.lock().choice.value.clone();
        log_info!(
            "[DNS-over-{} '{}'] {} ➜ {:?} ({} ms), ipList: {:?}",
            self.dns_type,
            self.dns_name,
            hostname,
            ip,
            start.elapsed().as_millis(),
            ip_list
        );

        if let Some(checker) = ip_checker {
            if let Some(ref ip) = ip {
                if *ip != hostname && checker(ip) {
                    return Some(ip.clone());
                }
            }
            for candidate in &ip_list {
                if candidate != hostname && checker(candidate) {
                    return Some(candidate.clone());
                }
            }
        }

        ip.or_else(|| Some(hostname.to_string()))
    }

    async fn lookup_with_preset(&self, hostname: &str, family: u8) -> anyhow::Result<Vec<String>> {
        log_debug!(
            "lookup_with_preset: dns={} hostname={} has_preset={}",
            self.dns_name,
            hostname,
            self.pre_set_ip_list.is_some()
        );
        if let Some(preset) = &self.pre_set_ip_list {
            if let Some(matched) = match_hostname(preset, hostname, "preSetIpList") {
                let list = matched
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .filter(|(_, v)| match v {
                                Value::Bool(b) => *b,
                                Value::String(s) => s != "false" && s != "0",
                                Value::Number(n) => n.as_f64().unwrap_or(0.0) > 0.0,
                                _ => true,
                            })
                            .map(|(k, _)| k.clone())
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                if !list.is_empty() {
                    log_info!(
                        "[DNS-over-PreSet '{}'] 使用预设IP: {} -> {:?}",
                        self.dns_name,
                        hostname,
                        list
                    );
                    return Ok(list);
                }
            }
        }
        match do_query(&self.transport, hostname, family).await {
            Ok(v) => Ok(v),
            Err(e) => {
                log_error!(
                    "[DNS-over-{} '{}'] cannot resolve {} : {}",
                    self.dns_type,
                    self.dns_name,
                    hostname,
                    e
                );
                Ok(Vec::new())
            }
        }
    }
}

// ---------------------------------------------------------------- DNS 管理

pub struct DnsMap {
    providers: HashMap<String, Arc<BaseDns>>,
    for_sni: Arc<BaseDns>,
}

impl DnsMap {
    pub fn get(&self, name: &str) -> Option<Arc<BaseDns>> {
        self.providers.get(name).cloned()
    }
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.providers.keys().cloned().collect();
        names.sort();
        names
    }
    pub fn for_sni(&self) -> Arc<BaseDns> {
        self.for_sni.clone()
    }
}

fn parse_host_port(server: &str) -> (String, Option<u16>) {
    let remains = server.split("://").last().unwrap_or(server).to_string();
    if remains.contains("]:") {
        let idx = remains.find("]:").unwrap();
        let host = remains[0..idx].trim_start_matches('[').to_string();
        let port = remains[idx + 2..].parse::<u16>().ok();
        (host, port)
    } else if is_ipv6(&remains) {
        (
            remains.trim_matches(|c| c == '[' || c == ']').to_string(),
            None,
        )
    } else if remains.contains(':') {
        let parts: Vec<&str> = remains.split(':').collect();
        (
            parts[0].to_string(),
            parts.get(1).and_then(|p| p.parse().ok()),
        )
    } else {
        (remains, None)
    }
}

pub fn init_dns(providers: &Value, pre_set_ip_list: Arc<DomainMap>) -> DnsMap {
    let mut map: HashMap<String, Arc<BaseDns>> = HashMap::new();
    let mut for_sni: Option<Arc<BaseDns>> = None;

    if let Value::Object(obj) = providers {
        for (provider, conf) in obj {
            let mut server = conf
                .get("server")
                .or_else(|| conf.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .replace(' ', "");
            if server.is_empty() {
                continue;
            }
            let mut type_name = conf
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if type_name.is_empty() {
                if server.starts_with("https://") || server.starts_with("http://") {
                    type_name = "https".to_string();
                } else if server.starts_with("tls://") || server.starts_with("dot://") {
                    type_name = "tls".to_string();
                } else if server.starts_with("tcp://") {
                    type_name = "tcp".to_string();
                } else {
                    type_name = "udp".to_string();
                }
            }
            let family: u8 = conf
                .get("family")
                .and_then(|v| v.as_i64())
                .and_then(|v| u8::try_from(v).ok())
                .unwrap_or(0);
            let cache_size = conf.get("cacheSize").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            // 查询结果缓存 TTL（秒）：provider 级 cacheTtl / cacheSeconds 覆盖，
            // 0 表示永不过期（保持旧行为）
            let cache_ttl = conf
                .get("cacheTtl")
                .or_else(|| conf.get("cacheSeconds"))
                .and_then(|v| v.as_u64())
                .unwrap_or(DEFAULT_DNS_CACHE_TTL_SECS);
            let sni_conf = conf
                .get("sni")
                .or_else(|| conf.get("servername"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let dns: BaseDns = if matches!(type_name.as_str(), "https" | "doh" | "dns-over-https") {
                let url = if server.contains('/') {
                    server.clone()
                } else {
                    format!("https://{}/dns-query", server)
                };
                BaseDns::new(
                    provider,
                    "HTTPS",
                    Transport::Https { url },
                    Some(pre_set_ip_list.clone()),
                    cache_ttl,
                )
            } else {
                let (host, port_opt) = parse_host_port(&server);
                server = host.clone();
                let _ = cache_size;
                match type_name.as_str() {
                    "tls" | "dot" | "dns-over-tls" => {
                        let port = port_opt
                            .or_else(|| conf.get("port").and_then(|v| v.as_u64()).map(|v| v as u16))
                            .unwrap_or(853);
                        BaseDns::new(
                            provider,
                            "TLS",
                            Transport::Tls {
                                server,
                                port,
                                servername: sni_conf.clone().unwrap_or_else(|| host.clone()),
                                verify: sni_conf.is_none(),
                            },
                            Some(pre_set_ip_list.clone()),
                            cache_ttl,
                        )
                    }
                    "tcp" => {
                        let port = port_opt
                            .or_else(|| conf.get("port").and_then(|v| v.as_u64()).map(|v| v as u16))
                            .unwrap_or(53);
                        BaseDns::new(
                            provider,
                            "TCP",
                            Transport::Tcp { server, port },
                            Some(pre_set_ip_list.clone()),
                            cache_ttl,
                        )
                    }
                    _ => {
                        let port = port_opt
                            .or_else(|| conf.get("port").and_then(|v| v.as_u64()).map(|v| v as u16))
                            .unwrap_or(53);
                        BaseDns::new(
                            provider,
                            "UDP",
                            Transport::Udp { server, port },
                            Some(pre_set_ip_list.clone()),
                            cache_ttl,
                        )
                    }
                }
            };

            let dns = Arc::new(dns);
            map.insert(provider.clone(), dns.clone());
            let _ = family;
            let for_sni_flag = conf
                .get("forSNI")
                .or_else(|| conf.get("forSni"))
                .map(|v| {
                    v.as_bool().unwrap_or(false) || v.as_str().map(|s| s == "true").unwrap_or(false)
                })
                .unwrap_or(false);
            if for_sni_flag {
                for_sni = Some(dns);
            }
        }
    }

    // PreSet 为静态映射，无需 TTL（传 0 表示不过期）
    let preset = Arc::new(BaseDns::new(
        "PreSet",
        "PreSet",
        Transport::PreSet,
        Some(pre_set_ip_list),
        0,
    ));
    map.insert("PreSet".to_string(), preset.clone());
    let for_sni = for_sni.unwrap_or_else(|| preset.clone());
    map.insert("ForSNI".to_string(), for_sni.clone());

    log_info!("设置SNI默认使用的DNS为 '{}'", for_sni.dns_name);
    DnsMap {
        providers: map,
        for_sni,
    }
}

pub struct DnsConfig {
    pub pre_set_ip_list: Arc<DomainMap>,
    pub dns_map: Arc<DnsMap>,
    pub mapping: Arc<DomainMap>,
    /// `dns.familyMapping`：域名 → "4"/"6"，覆盖默认地址族
    pub family_mapping: Option<Arc<DomainMap>>,
}

/// 对应原版 `getDNSAndFamily`
pub fn get_dns_and_family<'a>(
    dns_config: &'a DnsConfig,
    hostname: &str,
) -> Option<(Arc<BaseDns>, u8)> {
    log_debug!("get_dns_and_family: hostname={}", hostname);
    if match_hostname(&dns_config.pre_set_ip_list, hostname, "preSetIpList").is_some() {
        return Some((dns_config.dns_map.get("PreSet")?, 4));
    }
    let mapped = match_hostname(&dns_config.mapping, hostname, "dns mapping")?;
    // mapping 值支持两种形式（与原版一致）：
    // - 字符串：DNS 提供者名称，如 "*.github.com": "quad9"
    // - 对象：{ "dnsName": "quad9", "family": 6 }
    let (dns_name, mut family) = match mapped {
        Value::String(s) => (s.as_str(), 4u8),
        v => (
            v.get("dnsName").and_then(|x| x.as_str()).unwrap_or(""),
            v.get("family").and_then(|x| x.as_i64()).unwrap_or(4) as u8,
        ),
    };
    // familyMapping 命中时覆盖默认地址族（值为 "4"/"6" 字符串或数字）
    if let Some(fm) = &dns_config.family_mapping {
        if let Some(v) = match_hostname(fm, hostname, "dns familyMapping") {
            let parsed = match v {
                Value::String(s) => s.trim().parse::<u8>().ok(),
                Value::Number(n) => n.as_i64().map(|n| n as u8),
                _ => None,
            };
            if let Some(f) = parsed {
                family = f;
            }
        }
    }

    let dns = if dns_name == "usa" && dns_config.dns_map.get("usa").is_none() {
        dns_config.dns_map.get("cloudflare")?
    } else {
        dns_config.dns_map.get(dns_name)?
    };
    Some((dns, if family == 6 { 6 } else { 4 }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::domain_map_regexply;
    use std::time::{Duration, Instant};

    fn cache_with_ttl(ttl_secs: u64) -> IpCache {
        IpCache {
            choice: DynamicChoice::new("a.test"),
            lookup_count: 0,
            expires_at: if ttl_secs == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_secs))
            },
        }
    }

    /// TTL 为 0 时永不过期；有 TTL 时到期即过期
    #[test]
    fn ip_cache_ttl_expiry() {
        let never = cache_with_ttl(0);
        assert!(!never.is_expired(Instant::now() + Duration::from_secs(86400)));

        let short = cache_with_ttl(60);
        let now = Instant::now();
        assert!(!short.is_expired(now));
        assert!(short.is_expired(now + Duration::from_secs(61)));
    }

    /// provider 级 cacheTtl 生效；默认 60s；0 表示不过期
    #[test]
    fn base_dns_reads_cache_ttl() {
        let map = Arc::new(domain_map_regexply(None));
        let dns = BaseDns::new("t", "PreSet", Transport::PreSet, Some(map.clone()), 60);
        assert_eq!(dns.ttl, Some(Duration::from_secs(60)));

        let dns = BaseDns::new("t", "PreSet", Transport::PreSet, Some(map.clone()), 0);
        assert_eq!(dns.ttl, None);

        let providers = serde_json::json!({
            "custom": { "server": "tls://1.1.1.1", "cacheTtl": 5 }
        });
        let dm = init_dns(&providers, map);
        assert_eq!(dm.get("custom").unwrap().ttl, Some(Duration::from_secs(5)));
    }

    /// 缓存过期后应重新解析（lookup_count 重置为新缓存项的计数）
    #[tokio::test]
    async fn dns_cache_re_resolves_after_ttl() {
        let preset = Arc::new(domain_map_regexply(Some(&serde_json::json!({
            "a.test": { "1.2.3.4": true }
        }))));
        let dns = BaseDns::new("t", "PreSet", Transport::PreSet, Some(preset), 1);

        assert_eq!(
            dns.lookup("a.test", 4, None).await.as_deref(),
            Some("1.2.3.4")
        );
        // 第二次命中缓存，lookup_count 递增到 2
        assert_eq!(
            dns.lookup("a.test", 4, None).await.as_deref(),
            Some("1.2.3.4")
        );
        let entry = dns.cache.lock().get("a.test").cloned().unwrap();
        assert_eq!(entry.lock().lookup_count, 2, "第二次应命中缓存");

        // 等待 TTL 过期后重新解析：重建缓存项，计数重置为 1
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            dns.lookup("a.test", 4, None).await.as_deref(),
            Some("1.2.3.4")
        );
        let entry = dns.cache.lock().get("a.test").cloned().unwrap();
        assert_eq!(entry.lock().lookup_count, 1, "过期后应重新解析");
    }
}
