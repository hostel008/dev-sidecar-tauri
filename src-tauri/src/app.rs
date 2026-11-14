//! 全局应用状态与服务编排（对应原版 core/src/index.js）

use crate::config::ConfigStore;
use crate::dns::{init_dns, DnsConfig, DnsMap};
use crate::event::{emit_status, StatusKey};
use crate::matcher::{domain_map_regexply, DomainMap};
use crate::plugin::{GitPlugin, NodePlugin, PipPlugin};
use crate::proxy::interceptor::handle_script_intercept_config;
use crate::proxy::{ProxyServer, ServerOptions};
use crate::speed::SpeedTester;
use crate::sysproxy::SysProxyParams;
use crate::tls::CertificateAuthority;
use crate::util::paths;
use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

pub struct AppState {
    config: Arc<ConfigStore>,
    ca: OnceLock<Arc<CertificateAuthority>>,
    server: RwLock<Option<Arc<ProxyServer>>>,
    speed: RwLock<Option<Arc<SpeedTester>>>,
    plugin_status: RwLock<HashMap<String, bool>>,
    /// 系统代理是否已真正接管（供前端查询真实状态，避免依赖可能错过的状态事件）
    proxy_running: RwLock<bool>,
    init_lock: Mutex<()>,
    /// 服务 / 系统代理 / 插件生命周期串行锁：禁止插件改写外部配置与停止服务交错
    lifecycle_lock: Mutex<()>,
    /// 当前由本应用写入并需要恢复的插件；用于崩溃后对账
    active_plugins: RwLock<Vec<String>>,
}

static APP: OnceLock<AppState> = OnceLock::new();

pub fn init_state() -> &'static AppState {
    APP.get_or_init(|| AppState {
        config: Arc::new(ConfigStore::new().expect("配置初始化失败")),
        ca: OnceLock::new(),
        server: RwLock::new(None),
        speed: RwLock::new(None),
        plugin_status: RwLock::new(HashMap::new()),
        proxy_running: RwLock::new(false),
        init_lock: Mutex::new(()),
        lifecycle_lock: Mutex::new(()),
        active_plugins: RwLock::new(Vec::new()),
    })
}

pub fn config() -> &'static Arc<ConfigStore> {
    &init_state().config
}

pub fn ca() -> Option<Arc<CertificateAuthority>> {
    init_state().ca.get().cloned()
}

/// 确保 CA 已初始化（首次调用时生成/加载证书文件）
pub fn ensure_ca() -> Result<Arc<CertificateAuthority>> {
    if let Some(ca) = init_state().ca.get().cloned() {
        return Ok(ca);
    }
    let cache_size = config()
        .get()
        .pointer("/server/fakeServerMaxLength")
        .and_then(|v| v.as_u64())
        .unwrap_or(100) as usize;
    let ca = CertificateAuthority::init(&paths::ca_cert_path(), &paths::ca_key_path(), cache_size)?;
    let ca = Arc::new(ca);
    let _ = init_state().ca.set(ca.clone());
    Ok(ca)
}

pub fn is_ca_exists() -> bool {
    paths::ca_cert_path().exists() && paths::ca_key_path().exists()
}

pub fn can_trust_ca() -> bool {
    if !is_ca_exists() {
        return false;
    }
    match check_ca_trusted() {
        Ok(trusted) => trusted,
        Err(e) => {
            log_warn!("检查根证书信任状态失败: {}", e);
            false
        }
    }
}

/// 读取本地 CA 证书 DER（PEM 文件中的第一张证书）
fn read_ca_cert_der() -> Result<Vec<u8>> {
    let pem = std::fs::read_to_string(paths::ca_cert_path())?;
    let mut certs = rustls_pemfile::certs(&mut pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!certs.is_empty(), "证书文件中没有证书");
    Ok(certs.remove(0).to_vec())
}

/// 检查一段 PEM 文本中是否包含目标证书（DER 逐字节比较）。
/// 仅 macOS / Linux 的信任检查使用；Windows 走 certutil 序列号匹配
#[allow(dead_code)]
fn pem_contains_der(pem_text: &str, target_der: &[u8]) -> bool {
    rustls_pemfile::certs(&mut pem_text.as_bytes())
        .filter_map(|c| c.ok())
        .any(|c| c.as_ref() == target_der)
}

// ---- 极简 DER TLV 解析：仅用于提取证书序列号 ----

/// 拆分 TLV：返回 (content, 其余字节)
fn der_split(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let b0 = buf[1] as usize;
    let (len, hdr) = if b0 & 0x80 == 0 {
        (b0, 2usize)
    } else {
        let n = b0 & 0x7f;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | buf[2 + i] as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    Some((&buf[hdr..end], &buf[end..]))
}

/// 从证书 DER 中提取序列号的大写十六进制（去掉前导零字节）
/// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL, serialNumber INTEGER, ... }, ... }
fn der_serial_hex(der: &[u8]) -> Option<String> {
    let (body, _) = der_split(der)?; // 外层 SEQUENCE 的内容
    let (tbs, _) = der_split(body)?; // TBSCertificate
    let mut rest = tbs;
    if rest.first() == Some(&0xA0) {
        // 跳过 [0] EXPLICIT version
        rest = der_split(rest)?.1;
    }
    let (serial, _) = der_split(rest)?;
    let serial: Vec<u8> = serial.iter().skip_while(|&&b| b == 0).copied().collect();
    if serial.is_empty() {
        return None;
    }
    Some(serial.iter().map(|b| format!("{:02X}", b)).collect())
}

/// 真实检查本地 CA 证书是否已安装到系统信任区
#[cfg(target_os = "windows")]
fn check_ca_trusted() -> Result<bool> {
    let der = read_ca_cert_der()?;
    let serial = der_serial_hex(&der).ok_or_else(|| anyhow::anyhow!("无法解析证书序列号"))?;
    // 列出当前用户的 Root 存储，匹配证书序列号。
    // 注意：certutil -store <serial> 未命中时不会报错（仍列出 store 内容），不能靠退出码判断；
    // 输出为本地编码（GBK 等），但序列号是 ASCII 十六进制不受影响（certutil 输出为小写）
    let output = crate::util::hidden_command("certutil")
        .args(["-user", "-store", "Root"])
        .output()?;
    if !output.status.success() {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
    Ok(text.contains(&serial.to_lowercase()))
}

#[cfg(target_os = "macos")]
fn check_ca_trusted() -> Result<bool> {
    let der = read_ca_cert_der()?;
    // 搜索钥匙串中 CN 为 "DevSidecar CA" 的证书，逐张与本地证书比较
    let output = std::process::Command::new("security")
        .args(["find-certificate", "-a", "-c", "DevSidecar CA", "-p"])
        .output()?;
    if !output.status.success() {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(pem_contains_der(&text, &der))
}

#[cfg(target_os = "linux")]
fn check_ca_trusted() -> Result<bool> {
    let der = read_ca_cert_der()?;
    // 与安装逻辑对应：安装时把证书复制到 /usr/local/share/ca-certificates/dev-sidecar.crt
    let installed = std::fs::read_to_string("/usr/local/share/ca-certificates/dev-sidecar.crt")
        .unwrap_or_default();
    Ok(pem_contains_der(&installed, &der))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn check_ca_trusted() -> Result<bool> {
    Ok(false)
}

pub fn server_running() -> bool {
    init_state().server.read().is_some()
}

pub fn proxy_running() -> bool {
    *init_state().proxy_running.read()
}

/// 汇总当前真实运行状态，供前端主动拉取（前端可能错过启动阶段发出的状态事件）
pub fn status_snapshot() -> Value {
    json!({
        "server": server_running(),
        "proxy": proxy_running(),
        "node": plugin_status("node"),
        "git": plugin_status("git"),
        "pip": plugin_status("pip"),
    })
}

fn set_plugin_status(name: &str, enabled: bool) {
    init_state()
        .plugin_status
        .write()
        .insert(name.to_string(), enabled);
    sync_plugin_enabled_config(name, enabled);
}

/// 把三个插件的运行时状态回写到配置的 `plugin.<name>.enabled`。
/// 启动完成后调用，保证插件页开关与状态标签一致。
pub fn sync_plugin_state_to_config() {
    for name in ["node", "git", "pip"] {
        sync_plugin_enabled_config(name, plugin_status(name));
    }
}

/// 插件是否真正生效以运行时状态为准（外部配置已写入 / 已还原），
/// 这里把结果回写到配置的 `plugin.<name>.enabled`，避免“插件页开关（配置）”
/// 与“当前状态标签（运行时）”长期不一致：比如服务停止、启动恢复、
/// 首页一键加速等其他入口改变了运行时状态时，配置也跟着变。
fn sync_plugin_enabled_config(name: &str, enabled: bool) {
    let current = config()
        .get()
        .pointer(&format!("/plugin/{}/enabled", name))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if current == enabled {
        return;
    }
    let mut patch = serde_json::Map::new();
    patch.insert(name.to_string(), serde_json::json!({ "enabled": enabled }));
    if let Err(e) = config().update(serde_json::json!({ "plugin": patch })) {
        // 配置写不进去不影响插件本身的启停，只记日志
        log_error!("同步插件 {} 的 enabled 配置失败: {}", name, e);
    }
}

fn plugin_status(name: &str) -> bool {
    init_state()
        .plugin_status
        .read()
        .get(name)
        .copied()
        .unwrap_or(false)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RuntimeJournal {
    version: u32,
    #[serde(default)]
    active_plugins: Vec<String>,
    #[serde(default)]
    proxy_taken: bool,
    #[serde(default)]
    last_error: Option<String>,
}

fn load_journal() -> RuntimeJournal {
    match crate::util::managed::load_state::<RuntimeJournal>(&paths::runtime_state_path()) {
        Ok(Some(mut j)) => {
            if j.version == 0 {
                j.version = 1;
            }
            j
        }
        Ok(None) => RuntimeJournal {
            version: 1,
            ..Default::default()
        },
        Err(e) => {
            log_error!("读取运行 journal 失败，将按残留状态修复: {}", e);
            RuntimeJournal {
                version: 1,
                // 状态损坏时仍检查两类外部配置，避免把安全判断建立在不完整 journal 上
                proxy_taken: crate::util::paths::sysproxy_managed_state_path().exists(),
                ..Default::default()
            }
        }
    }
}

fn save_journal(journal: &RuntimeJournal) -> Result<()> {
    crate::util::managed::save_state(&paths::runtime_state_path(), journal)
}

fn journal_add_plugin(name: &str) {
    let mut active = init_state().active_plugins.write();
    if !active.iter().any(|n| n == name) {
        active.push(name.to_string());
    }
}

fn journal_remove_plugin(name: &str) {
    init_state().active_plugins.write().retain(|n| n != name);
}

fn active_plugin_names() -> Vec<String> {
    init_state().active_plugins.read().clone()
}

fn plugin_status_key(name: &str) -> StatusKey {
    match name {
        "node" => StatusKey::Node,
        "git" => StatusKey::Git,
        _ => StatusKey::Pip,
    }
}

fn validate_plugin_name(name: &str) -> Result<()> {
    match name {
        "node" | "git" | "pip" => Ok(()),
        _ => anyhow::bail!("未知插件: {}", name),
    }
}

// ------------------------------------------------------------------ 初始化

pub async fn init() -> Result<()> {
    let _guard = init_state().init_lock.lock().await;

    let cfg = config().clone();
    // 远程配置下载
    if let Err(e) = cfg.download_remote_config().await {
        log_error!("下载远程配置失败: {}", e);
        emit_status(StatusKey::RemoteConfig, "error");
    } else {
        emit_status(StatusKey::RemoteConfig, "success");
    }
    cfg.reload();

    // 初始化 CA
    let cache_size = cfg
        .get()
        .pointer("/server/fakeServerMaxLength")
        .and_then(|v| v.as_u64())
        .unwrap_or(100) as usize;
    match CertificateAuthority::init(&paths::ca_cert_path(), &paths::ca_key_path(), cache_size) {
        Ok(ca) => {
            let _ = init_state().ca.set(Arc::new(ca));
        }
        Err(e) => {
            log_error!("初始化 CA 证书失败: {}", e);
            return Err(e);
        }
    }

    // 先对账上次异常退出留下的外部配置；恢复不完整时本次不自动接管，
    // 避免在未知残留之上继续覆盖用户配置。
    let recovery_ok = match recover_previous_runtime().await {
        Ok(()) => true,
        Err(e) => {
            log_error!("恢复上次运行的残留配置失败: {}", e);
            emit_status(StatusKey::Proxy, "fail");
            false
        }
    };

    // 启动加速服务；系统代理与插件均以「服务是否真正启动」为准
    let server_started = if server_setting_enabled() {
        match start_server().await {
            Ok(_) => true,
            Err(e) => {
                log_error!("启动加速服务失败: {}", e);
                emit_status(StatusKey::Server, "fail");
                false
            }
        }
    } else {
        false
    };

    // 系统代理指向本地加速服务，服务未启动时不接管，避免全系统流量指向死端口
    let will_takeover = recovery_ok && server_started && proxy_setting_enabled();
    if will_takeover {
        if let Err(e) = start_proxy().await {
            log_error!("接管系统代理失败: {}", e);
            // 接管失败时若上次残留仍指向本应用端口，清除之，避免流量指向死端口
            cleanup_residual_proxy().await;
        }
    } else {
        // 上次异常退出（强杀 / 崩溃 / 关机）可能残留系统代理与环境变量，
        // 本次不接管时自动清除，否则全系统流量会持续指向未监听的本地端口
        cleanup_residual_proxy().await;
    }

    // 插件：与主服务保持一致，服务未启动则不拉起（首次启动默认也不启动）
    let cfg_value = cfg.get();
    if recovery_ok && server_started {
        for name in ["node", "git", "pip"] {
            if plugin_start_with_app(&cfg_value, name) {
                if let Err(e) = enable_plugin(name).await {
                    log_error!("随应用启动插件 {} 失败: {}", name, e);
                    emit_status(plugin_status_key(name), "fail");
                }
            }
        }
    }

    // 启动完成后把运行时状态对齐到配置：上次会话里 `enabled=true` 但没勾选
    // 「随应用启动」的插件本次并未启用，配置要改成 false，否则插件页开关会显示为开
    // 而状态标签显示未启用。
    sync_plugin_state_to_config();

    Ok(())
}

fn server_setting_enabled() -> bool {
    config()
        .get()
        .pointer("/server/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

pub fn proxy_setting_enabled() -> bool {
    config()
        .get()
        .pointer("/proxy/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// 插件是否设置为「随应用启动」
pub fn plugin_start_with_app(cfg: &Value, name: &str) -> bool {
    cfg.pointer(&format!("/plugin/{}/startWithApp", name))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

// ------------------------------------------------------------------ 服务

/// 依据配置构建 ServerOptions
pub fn build_server_options(cfg: &Value) -> Result<(Arc<ServerOptions>, Arc<DnsMap>)> {
    let mut setting = cfg
        .pointer("/server/setting")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    // 脚本目录
    let script_dir = paths::user_base_path().join("extra").join("scripts");
    if let Some(Value::Object(map)) = setting.get_mut("script") {
        map.insert(
            "dirAbsolutePath".to_string(),
            Value::String(script_dir.to_string_lossy().replace('\\', "/")),
        );
    }

    let intercept_enabled = cfg
        .pointer("/server/intercept/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut intercepts_value = cfg
        .pointer("/server/intercepts")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    if intercept_enabled {
        handle_script_intercept_config(&mut intercepts_value);
    } else {
        intercepts_value = serde_json::json!({});
    }

    let white_list_value = if intercept_enabled {
        cfg.pointer("/server/whiteList")
            .cloned()
            .unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({ ".*": true })
    };
    let _ = std::fs::create_dir_all(&script_dir);

    let pre_set_ip_list = Arc::new(domain_map_regexply(cfg.pointer("/server/preSetIpList")));
    let sni_list = Arc::new(domain_map_regexply(
        cfg.pointer("/server/compatible/connect"),
    ));

    let dns_map = Arc::new(init_dns(
        cfg.pointer("/server/dns/providers")
            .unwrap_or(&serde_json::json!({})),
        pre_set_ip_list.clone(),
    ));

    let dns_config = DnsConfig {
        pre_set_ip_list: pre_set_ip_list.clone(),
        dns_map: dns_map.clone(),
        mapping: Arc::new(domain_map_regexply(cfg.pointer("/server/dns/mapping"))),
        family_mapping: Some(Arc::new(domain_map_regexply(
            cfg.pointer("/server/dns/familyMapping"),
        ))),
    };

    let speed = Arc::new(SpeedTester::new(dns_map.clone(), cfg));
    *init_state().speed.write() = Some(speed.clone());

    let opts = ServerOptions {
        host: cfg
            .pointer("/server/host")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1")
            .to_string(),
        port: cfg
            .pointer("/server/port")
            .and_then(|v| v.as_u64())
            .unwrap_or(31181) as u16,
        dns_config,
        setting,
        intercepts: Arc::new(domain_map_regexply(Some(&intercepts_value))),
        white_list: Arc::new(domain_map_regexply(Some(&white_list_value))),
        sni_list,
        speed: Some(speed),
        fake_server_max_length: cfg
            .pointer("/server/fakeServerMaxLength")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize,
    };
    Ok((Arc::new(opts), dns_map))
}

async fn ensure_listening(cfg: &Value) -> Result<()> {
    let host = cfg
        .pointer("/server/host")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1");
    let host = if host == "0.0.0.0" || host.is_empty() {
        "127.0.0.1"
    } else {
        host
    };
    let port = cfg
        .pointer("/server/port")
        .and_then(|v| v.as_u64())
        .unwrap_or(31181) as u16;
    let addr = format!("{}:{}", host, port);
    match tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => anyhow::bail!("加速服务未在 {} 监听: {}", addr, e),
        Err(_) => anyhow::bail!("连接加速服务 {} 超时，拒绝接管系统代理", addr),
    }
}

fn persist_journal() -> Result<()> {
    save_journal(&RuntimeJournal {
        version: 1,
        active_plugins: active_plugin_names(),
        proxy_taken: proxy_running(),
        last_error: None,
    })
}

async fn start_server_locked() -> Result<()> {
    if server_running() {
        log_warn!("加速服务已在运行中");
        return Ok(());
    }
    emit_status(StatusKey::Server, "starting");
    let cfg = config().get();
    let (opts, _dns_map) = build_server_options(&cfg)?;

    match ProxyServer::start(opts.clone()).await {
        Ok(server) => {
            let server = Arc::new(server);
            *init_state().server.write() = Some(server.clone());
            if let Err(e) = ensure_listening(&cfg).await {
                // 监听未就绪时不能把半启动的服务留在状态里，否则前端会显示
                // “运行中”，而系统代理可能已经指向一个不可用的端口。
                server.stop().await;
                *init_state().server.write() = None;
                emit_status(StatusKey::Server, "fail");
                return Err(e);
            }
            emit_status(StatusKey::Server, "success");
            log_info!("加速服务启动成功，本地端口已通过连通性检查");
            if let Some(speed) = &opts.speed {
                speed.clone().start_background();
            }
            Ok(())
        }
        Err(e) => {
            emit_status(StatusKey::Server, "fail");
            Err(e)
        }
    }
}

pub async fn start_server() -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    start_server_locked().await
}

async fn stop_proxy_locked() -> Result<()> {
    let params = build_sysproxy_params(&config().get());
    match crate::sysproxy::teardown_proxy(params).await {
        Ok(_) => {
            *init_state().proxy_running.write() = false;
            emit_status(StatusKey::Proxy, "stopped");
            persist_journal()?;
            log_info!("关闭系统代理成功");
            Ok(())
        }
        Err(e) => {
            emit_status(StatusKey::Proxy, "fail");
            Err(e)
        }
    }
}

async fn stop_server_locked() -> Result<()> {
    // 即使监听已停止，也要撤销 journal/真实状态中仍活动的外部引用。
    // 先撤销所有实际的活动引用，任何一个失败都不停止监听，避免把外部配置指向死端口。
    let mut names = active_plugin_names();
    for name in ["node", "git", "pip"] {
        if plugin_status(name) && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    let mut errors = Vec::new();
    for name in names {
        if let Err(e) = disable_plugin_locked(&name).await {
            errors.push(format!("{}: {}", name, e));
        }
    }
    if !errors.is_empty() {
        anyhow::bail!("撤销插件配置失败，服务保持运行: {}", errors.join("; "));
    }

    let params = build_sysproxy_params(&config().get());
    if proxy_running()
        || crate::util::paths::sysproxy_managed_state_path().exists()
        || crate::sysproxy::has_residual_proxy(params.https_port, params.http_port)
    {
        if let Err(e) = stop_proxy_locked().await {
            anyhow::bail!("恢复系统代理失败，服务保持运行: {}", e);
        }
    }

    let server = init_state().server.write().take();
    if let Some(server) = server {
        server.stop().await;
        emit_status(StatusKey::Server, "stopped");
        log_info!("加速服务已停止");
    }
    persist_journal()?;
    Ok(())
}

pub async fn stop_server() -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    stop_server_locked().await
}

/// 清理上次异常退出遗留的系统代理（仅当系统代理或事务快照仍指向本应用时执行）
async fn cleanup_residual_proxy() {
    let params = build_sysproxy_params(&config().get());
    let has_state = crate::util::paths::sysproxy_managed_state_path().exists();
    if !has_state && !crate::sysproxy::has_residual_proxy(params.https_port, params.http_port) {
        return;
    }
    log_warn!(
        "检测到上次残留的系统代理/快照（{}:{}），正在恢复",
        params.ip,
        params.https_port
    );
    if let Err(e) = stop_proxy().await {
        log_error!("清除残留系统代理失败: {}", e);
    }
}

/// 启动阶段先恢复上次异常退出可能留下的外部配置，再决定是否重新接管。
pub async fn recover_previous_runtime() -> Result<()> {
    let cfg = config().get();
    let mut journal = load_journal();
    let mut errors = Vec::new();

    let mut remaining: Vec<String> = Vec::new();
    // NPM 快照无论 journal 是否记录都要恢复，防止 journal 写入前/后崩溃。
    let npm_had_state = paths::npm_managed_state_path().exists();
    if let Err(e) = crate::plugin::recover_npm_state(&cfg).await {
        errors.push(format!("npm: {}", e));
        if !remaining.iter().any(|n| n == "node") {
            remaining.push("node".to_string());
        }
    }
    // Git/PIP 同样按快照恢复，避免 journal 尚未写入时崩溃导致用户配置永久被改。
    let git_had_state = paths::git_managed_state_path().exists();
    if git_had_state {
        if let Err(e) = GitPlugin::close_proxy(&cfg).await {
            errors.push(format!("git: {}", e));
            remaining.push("git".to_string());
        }
    }
    let pip_had_state = paths::pip_managed_state_path().exists();
    if pip_had_state {
        if let Err(e) = PipPlugin::close_proxy(&cfg).await {
            errors.push(format!("pip: {}", e));
            remaining.push("pip".to_string());
        }
    }

    for name in journal.active_plugins.clone() {
        if (name == "node" && npm_had_state)
            || (name == "git" && git_had_state)
            || (name == "pip" && pip_had_state)
        {
            // 快照已完成恢复，无需再按旧逻辑清理用户后来重新设置的值。
            continue;
        }
        let result = match name.as_str() {
            "node" => NodePlugin::close_proxy(&cfg).await,
            "git" => GitPlugin::close_proxy(&cfg).await,
            "pip" => PipPlugin::close_proxy(&cfg).await,
            _ => Ok(()),
        };
        if let Err(e) = result {
            errors.push(format!("{}: {}", name, e));
            remaining.push(name);
        }
    }

    let params = build_sysproxy_params(&cfg);
    if journal.proxy_taken
        || paths::sysproxy_managed_state_path().exists()
        || crate::sysproxy::has_residual_proxy(params.https_port, params.http_port)
    {
        if let Err(e) = crate::sysproxy::teardown_proxy(params.clone()).await {
            errors.push(format!("sysproxy: {}", e));
        } else {
            *init_state().proxy_running.write() = false;
            journal.proxy_taken = false;
        }
    }

    *init_state().active_plugins.write() = remaining.clone();
    if errors.is_empty() {
        let _ = std::fs::remove_file(paths::runtime_state_path());
        log_info!("上次运行的外部配置已对账并恢复");
        Ok(())
    } else {
        journal.active_plugins = remaining;
        journal.proxy_taken = crate::util::paths::sysproxy_managed_state_path().exists()
            || crate::sysproxy::has_residual_proxy(params.https_port, params.http_port);
        journal.last_error = Some(errors.join("; "));
        let _ = save_journal(&journal);
        anyhow::bail!(
            "上次运行的残留配置未能完全恢复，请点击“修复残留配置”: {}",
            errors.join("; ")
        )
    }
}

/// 前端“修复残留配置”入口：停止残留监听并恢复外部配置，返回是否仍有残留。
pub async fn repair_residual_config() -> Result<Value> {
    let _guard = init_state().lifecycle_lock.lock().await;
    if server_running() {
        anyhow::bail!("请先停止加速服务，再修复残留配置");
    }
    match recover_previous_runtime().await {
        Ok(()) => Ok(json!({ "repaired": true, "residual": [] })),
        Err(e) => Ok(json!({
            "repaired": false,
            "residual": [e.to_string()],
        })),
    }
}

/// 应用退出前的清理：撤销所有实际活动引用、恢复系统代理、停止服务。
/// 即使配置已被前端改成 false，也以 journal/真实状态为准。
pub async fn shutdown() {
    let _guard = init_state().lifecycle_lock.lock().await;
    let params = build_sysproxy_params(&config().get());
    let mut names = active_plugin_names();
    for name in ["node", "git", "pip"] {
        if plugin_status(name) && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    for name in names {
        if let Err(e) = disable_plugin_locked(&name).await {
            log_error!("退出时回滚插件 {} 失败: {}", name, e);
        }
    }
    if proxy_running()
        || paths::sysproxy_managed_state_path().exists()
        || crate::sysproxy::has_residual_proxy(params.https_port, params.http_port)
    {
        if let Err(e) = stop_proxy_locked().await {
            log_error!("退出时关闭系统代理失败: {}", e);
        }
    }
    let server = init_state().server.write().take();
    if let Some(server) = server {
        server.stop().await;
    }
    if active_plugin_names().is_empty()
        && !crate::util::paths::sysproxy_managed_state_path().exists()
    {
        let _ = std::fs::remove_file(paths::runtime_state_path());
    } else if let Err(e) = persist_journal() {
        log_error!("保存退出 journal 失败: {}", e);
    }
}

pub async fn restart_server() -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    let was_running = server_running();
    let proxy_on = proxy_running();
    let active = active_plugin_names();

    stop_server_locked().await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    start_server_locked().await?;
    let mut errors = Vec::new();
    for name in active {
        if let Err(e) = enable_plugin_locked(&name).await {
            errors.push(format!("{}: {}", name, e));
        }
    }
    if proxy_on {
        if let Err(e) = start_proxy_locked().await {
            errors.push(format!("proxy: {}", e));
        }
    }
    if was_running && errors.is_empty() {
        log_info!("加速服务重启完成");
        Ok(())
    } else if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("服务已启动，但恢复部分外部配置失败: {}", errors.join("; "))
    }
}

/// 首页“一键加速”的后端编排：服务 → 系统代理 → 随应用启动插件。
/// 任一步失败都会回滚本次新增的代理/插件，避免半启动状态。
pub async fn start_acceleration() -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    let was_running = server_running();
    let was_proxy = proxy_running();
    let linked: Vec<String> = ["node", "git", "pip"]
        .iter()
        .filter(|name| plugin_start_with_app(&config().get(), name))
        .filter(|name| !plugin_status(name))
        .map(|name| name.to_string())
        .collect();
    let mut started_plugins: Vec<String> = Vec::new();

    let result: Result<()> = async {
        start_server_locked().await?;
        if !proxy_running() {
            start_proxy_locked().await?;
        }
        for name in &linked {
            enable_plugin_locked(name).await?;
            started_plugins.push(name.clone());
        }
        Ok(())
    }
    .await;

    if let Err(e) = result {
        for name in started_plugins {
            if let Err(re) = disable_plugin_locked(&name).await {
                log_error!("回滚插件 {} 失败: {}", name, re);
            }
        }
        if !was_proxy && proxy_running() {
            if let Err(re) = stop_proxy_locked().await {
                log_error!("回滚系统代理失败: {}", re);
            }
        }
        if !was_running && server_running() {
            if let Err(re) = stop_server_locked().await {
                log_error!("回滚加速服务失败: {}", re);
            }
        }
        anyhow::bail!("一键加速失败，已回滚本次改动: {}", e);
    }
    Ok(())
}

/// 首页“停止加速”的后端编排：插件 → 系统代理 → 服务，顺序不可由前端改变。
pub async fn stop_acceleration() -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    stop_server_locked().await
}

// ------------------------------------------------------------------ 系统代理

fn build_sysproxy_params(cfg: &Value) -> SysProxyParams {
    let port = cfg
        .pointer("/server/port")
        .and_then(|v| v.as_u64())
        .unwrap_or(31181) as u16;
    let http_port = if port > 0 { port - 1 } else { 0 };
    let ip = cfg
        .pointer("/server/host")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1")
        .to_string();

    let mut exclude_list: Vec<String> = Vec::new();
    if let Some(Value::Object(list)) = cfg.pointer("/proxy/excludeIpList") {
        for (k, v) in list {
            if v.as_bool().unwrap_or(false) || v.as_str() == Some("true") {
                exclude_list.push(k.clone());
            }
        }
    }

    SysProxyParams {
        ip,
        https_port: port,
        http_port,
        proxy_http: cfg
            .pointer("/proxy/proxyHttp")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        exclude_list,
        set_env: cfg
            .pointer("/proxy/setEnv")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        set_ca_bundle: cfg
            .pointer("/proxy/setCaBundle")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        ca_cert_path: cfg
            .pointer("/server/setting/rootCaFile/certPath")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    }
}

async fn start_proxy_locked() -> Result<()> {
    if !server_running() {
        anyhow::bail!("加速服务未运行，拒绝接管系统代理");
    }
    let cfg = config().get();
    ensure_listening(&cfg).await?;
    emit_status(StatusKey::Proxy, "starting");
    let params = build_sysproxy_params(&cfg);
    match crate::sysproxy::setup_proxy(Some(params)).await {
        Ok(_) => {
            *init_state().proxy_running.write() = true;
            persist_journal()?;
            emit_status(StatusKey::Proxy, "success");
            log_info!("开启系统代理成功");
            Ok(())
        }
        Err(e) => {
            emit_status(StatusKey::Proxy, "fail");
            Err(e)
        }
    }
}

pub async fn start_proxy() -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    start_proxy_locked().await
}

pub async fn stop_proxy() -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    stop_proxy_locked().await
}

// ------------------------------------------------------------------ 插件

async fn enable_plugin_locked(name: &str) -> Result<()> {
    validate_plugin_name(name)?;
    if !server_running() {
        anyhow::bail!("加速服务未运行，不能启用插件 {}", name);
    }
    let cfg = config().get();
    let port = cfg
        .pointer("/server/port")
        .and_then(|v| v.as_u64())
        .unwrap_or(31181) as u16;
    let ip = cfg
        .pointer("/server/host")
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1")
        .to_string();

    match name {
        "node" => NodePlugin::open_proxy(&cfg, &ip, port).await?,
        "git" => GitPlugin::open_proxy(&cfg, &ip, port).await?,
        "pip" => PipPlugin::open_proxy(&cfg, &ip, port).await?,
        _ => unreachable!(),
    }
    set_plugin_status(name, true);
    journal_add_plugin(name);
    persist_journal()?;
    emit_status(plugin_status_key(name), "success");
    Ok(())
}

pub async fn enable_plugin(name: &str) -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    enable_plugin_locked(name).await
}

async fn disable_plugin_locked(name: &str) -> Result<()> {
    validate_plugin_name(name)?;
    let cfg = config().get();
    match name {
        "node" => NodePlugin::close_proxy(&cfg).await?,
        "git" => GitPlugin::close_proxy(&cfg).await?,
        "pip" => PipPlugin::close_proxy(&cfg).await?,
        _ => unreachable!(),
    }
    set_plugin_status(name, false);
    journal_remove_plugin(name);
    persist_journal()?;
    emit_status(plugin_status_key(name), "stopped");
    Ok(())
}

pub async fn disable_plugin(name: &str) -> Result<()> {
    let _guard = init_state().lifecycle_lock.lock().await;
    disable_plugin_locked(name).await
}

pub fn plugin_enabled(name: &str) -> bool {
    plugin_status(name)
}

pub fn speed_tester() -> Option<Arc<SpeedTester>> {
    init_state().speed.read().clone()
}

pub fn set_config_value(cfg: Value) {
    config().set(cfg);
}

pub fn empty_domain_map() -> DomainMap {
    domain_map_regexply(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 带 [0] EXPLICIT version 的最小证书结构，序列号 01AB → "01AB"
    #[test]
    fn der_serial_hex_with_version() {
        // SEQUENCE { SEQUENCE { [0] { INTEGER 2 }, INTEGER 0x01AB } }
        let der = [
            0x30, 0x0B, // outer SEQUENCE, len 11
            0x30, 0x09, // tbsCertificate SEQUENCE, len 9
            0xA0, 0x03, 0x02, 0x01, 0x02, // [0] EXPLICIT version
            0x02, 0x02, 0x01, 0xAB, // serialNumber INTEGER
        ];
        assert_eq!(der_serial_hex(&der), Some("01AB".to_string()));
    }

    /// 无 version 字段（DER 默认 v1），前导零字节应被去掉：00 0F → "0F"
    #[test]
    fn der_serial_hex_without_version() {
        // SEQUENCE { SEQUENCE { INTEGER 0x000F } }
        let der = [
            0x30, 0x06, // outer SEQUENCE, len 6
            0x30, 0x04, // tbsCertificate SEQUENCE, len 4
            0x02, 0x02, 0x00, 0x0F, // serialNumber INTEGER（带前导零）
        ];
        assert_eq!(der_serial_hex(&der), Some("0F".to_string()));
    }

    /// 长度字段使用长格式（0x82 表示后跟 2 字节长度）时可正确解析
    #[test]
    fn der_split_long_form_length() {
        let mut der = vec![0x30, 0x82, 0x00, 0x03]; // SEQUENCE, len 3（长形式）
        der.extend_from_slice(&[0x01, 0x02, 0x03]);
        let (content, rest) = der_split(&der).unwrap();
        assert_eq!(content, &[0x01, 0x02, 0x03]);
        assert!(rest.is_empty());
    }
}
