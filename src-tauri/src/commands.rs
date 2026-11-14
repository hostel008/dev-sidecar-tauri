//! Tauri IPC 命令（对应原版 GUI 与 core 之间的 bridge）

use crate::app;
use crate::event::traffic;
use crate::util::paths;
use serde_json::json;
use serde_json::Value;
use tauri::Manager;
use tauri_plugin_opener::OpenerExt;

#[tauri::command]
pub fn get_config() -> Value {
    app::config().get()
}

#[tauri::command]
pub fn get_config_by_path(path: String) -> Value {
    crate::util::get_by_path(&app::config().get(), &path)
        .cloned()
        .unwrap_or(Value::Null)
}

#[tauri::command]
pub fn save_config(config: Value) -> Result<Value, String> {
    app::config()
        .save(config)
        .map(|(_diff, all)| all)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn reset_default(key: Option<String>) -> Result<Value, String> {
    app::config()
        .reset_default(key.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn remove_user_config() -> Result<bool, String> {
    app::config()
        .remove_user_config()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn download_remote_config() -> Result<Value, String> {
    app::config()
        .download_remote_config()
        .await
        .map_err(|e| e.to_string())?;
    Ok(app::config().reload())
}

#[tauri::command]
pub async fn start_server() -> Result<(), String> {
    app::start_server().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_server() -> Result<(), String> {
    app::stop_server().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn start_acceleration() -> Result<(), String> {
    app::start_acceleration().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_acceleration() -> Result<(), String> {
    app::stop_acceleration().await.map_err(|e| e.to_string())
}

/// 修复上次异常退出留下的系统代理、环境变量和 npm 配置残留。
#[tauri::command]
pub async fn repair_residual_config() -> Result<Value, String> {
    app::repair_residual_config()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn restart_server() -> Result<(), String> {
    app::restart_server().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn server_status() -> Value {
    json!({ "running": app::server_running() })
}

/// 汇总当前真实运行状态（server / proxy / 各插件）
#[tauri::command]
pub fn app_status() -> Value {
    app::status_snapshot()
}

/// 用系统默认程序打开文件或目录。
/// 不走 opener 插件的 IPC 命令，避免其 scope 校验拦截应用自身的目录 / 证书文件
#[tauri::command]
pub fn open_path(app: tauri::AppHandle, path: String) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("路径为空".to_string());
    }
    app.opener()
        .open_path(path, None::<String>)
        .map_err(|e| e.to_string())
}

/// 用系统默认浏览器打开链接
#[tauri::command]
pub fn open_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    app.opener()
        .open_url(url, None::<String>)
        .map_err(|e| e.to_string())
}

/// 日志状态（是否禁用、日志目录）
#[tauri::command]
pub fn get_log_status() -> Value {
    json!({
        "disabled": crate::util::log::is_disabled(),
        "dir": paths::log_dir().to_string_lossy().to_string(),
    })
}

/// 禁用 / 启用日志：写回配置并立即生效
#[tauri::command]
pub fn set_log_disabled(disabled: bool) -> Result<Value, String> {
    let mut next = app::config().get();
    if !next.is_object() {
        next = json!({});
    }
    let app_cfg = next
        .as_object_mut()
        .unwrap()
        .entry("app")
        .or_insert_with(|| json!({}));
    if !app_cfg.is_object() {
        *app_cfg = json!({});
    }
    app_cfg
        .as_object_mut()
        .unwrap()
        .insert("logDisabled".to_string(), json!(disabled));

    let all = app::config()
        .save(next)
        .map(|(_diff, all)| all)
        .map_err(|e| e.to_string())?;
    // save 内部会应用日志设置，这里再兜底一次，确保立即生效
    crate::util::log::set_disabled(disabled);
    Ok(json!({
        "disabled": crate::util::log::is_disabled(),
        "config": all,
    }))
}

/// 退出应用：先恢复系统代理 / 回滚插件配置 / 停止服务，再退出
#[tauri::command]
pub async fn shutdown(app: tauri::AppHandle) {
    app::shutdown().await;
    app.exit(0);
}

/// 执行关闭弹窗中选择的行为：exit=退出应用，hide=最小化到托盘
#[tauri::command]
pub async fn execute_close(app: tauri::AppHandle, action: String) {
    if action == "exit" {
        app::shutdown().await;
        app.exit(0);
    } else if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

/// 应用窗口尺寸：将 app.windowSize 立即应用到主窗口（「保存并应用」与启动恢复时调用）。
/// 宽高下限与 tauri.conf.json 的 minWidth/minHeight 对齐，并按当前显示器大小封顶。
#[tauri::command]
pub fn apply_window_size(app: tauri::AppHandle) -> Result<(), String> {
    let cfg = app::config().get();
    let size = cfg.pointer("/app/windowSize").cloned().unwrap_or_default();
    let width = size.get("width").and_then(|v| v.as_f64()).unwrap_or(900.0);
    let height = size.get("height").and_then(|v| v.as_f64()).unwrap_or(750.0);

    let window = app.get_webview_window("main").ok_or("主窗口不存在")?;
    let mut w = width.max(900.0);
    let mut h = height.max(620.0);
    if let Ok(Some(monitor)) = window.current_monitor() {
        let scale = window.scale_factor().unwrap_or(1.0);
        let logical = monitor.size().to_logical::<f64>(scale);
        w = w.min(logical.width);
        h = h.min(logical.height);
    }

    window
        .set_size(tauri::LogicalSize::new(w, h))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn start_proxy() -> Result<(), String> {
    app::start_proxy().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_proxy() -> Result<(), String> {
    app::stop_proxy().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn is_ca_exists() -> bool {
    app::is_ca_exists()
}

#[tauri::command]
pub fn can_trust_ca() -> bool {
    app::can_trust_ca()
}

#[tauri::command]
pub fn get_ca_cert_path() -> String {
    paths::ca_cert_path().to_string_lossy().to_string()
}

#[tauri::command]
pub fn get_user_base_path() -> String {
    paths::user_base_path().to_string_lossy().to_string()
}

/// 安装根证书到系统信任区
#[tauri::command]
pub fn setup_ca() -> Result<String, String> {
    let cert = paths::ca_cert_path();
    if !cert.exists() {
        return Err("根证书文件不存在，请先启动一次加速服务".to_string());
    }
    let path = cert.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    {
        let output = crate::util::hidden_command("certutil")
            .args(["-user", "-addstore", "Root", &path])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        return Ok("已将根证书添加到 Windows 受信任的根证书颁发机构".to_string());
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("security")
            .args([
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                &format!(
                    "{}/Library/Keychains/login.keychain",
                    dirs::home_dir().unwrap_or_default().to_string_lossy()
                ),
                &path,
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        return Ok("已将根证书添加到 macOS 钥匙串".to_string());
    }

    #[cfg(target_os = "linux")]
    {
        let dest = std::path::PathBuf::from("/usr/local/share/ca-certificates/dev-sidecar.crt");
        std::fs::copy(&cert, &dest).map_err(|e| e.to_string())?;
        let output = std::process::Command::new("update-ca-certificates")
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }
        return Ok("已将根证书添加到系统信任区".to_string());
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    Err("当前平台暂不支持自动安装根证书".to_string())
}

#[tauri::command]
pub async fn enable_plugin(name: String) -> Result<(), String> {
    app::enable_plugin(&name).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn disable_plugin(name: String) -> Result<(), String> {
    app::disable_plugin(&name).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn plugin_status() -> Value {
    json!({
        "node": app::plugin_enabled("node"),
        "git": app::plugin_enabled("git"),
        "pip": app::plugin_enabled("pip"),
    })
}

#[tauri::command]
pub async fn speed_test() -> Result<Value, String> {
    let Some(tester) = app::speed_tester() else {
        return Err("测速器未初始化".to_string());
    };
    let results = tester.run_once().await;
    Ok(json!({ "resultList": results.iter().map(|r| r.to_json()).collect::<Vec<_>>() }))
}

#[tauri::command]
pub fn traffic_stats() -> Value {
    let t = traffic();
    json!({
        "upload": t.upload.load(std::sync::atomic::Ordering::Relaxed),
        "download": t.download.load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[tauri::command]
pub fn reset_traffic() {
    traffic().reset();
}

#[tauri::command]
pub fn dns_providers() -> Value {
    let cfg = app::config().get();
    cfg.pointer("/server/dns/providers")
        .cloned()
        .unwrap_or(json!({}))
}

/// 简易网络检测：DNS + TCP + TLS
#[tauri::command]
pub async fn network_check(hostname: String) -> Value {
    let start = std::time::Instant::now();

    let dns_result =
        crate::speed::tcp_ping(&hostname, 443, std::time::Duration::from_millis(3000)).await;

    let ip_future = async {
        let cfg = app::config().get();
        let pre_set = crate::matcher::domain_map_regexply(cfg.pointer("/server/preSetIpList"));
        let dns_map = crate::dns::init_dns(
            cfg.pointer("/server/dns/providers").unwrap_or(&json!({})),
            std::sync::Arc::new(pre_set),
        );
        let mapping = crate::matcher::domain_map_regexply(cfg.pointer("/server/dns/mapping"));
        let dns_config = crate::dns::DnsConfig {
            pre_set_ip_list: std::sync::Arc::new(crate::matcher::domain_map_regexply(
                cfg.pointer("/server/preSetIpList"),
            )),
            dns_map: std::sync::Arc::new(dns_map),
            mapping: std::sync::Arc::new(mapping),
            family_mapping: Some(std::sync::Arc::new(crate::matcher::domain_map_regexply(
                cfg.pointer("/server/dns/familyMapping"),
            ))),
        };
        crate::dns::get_dns_and_family(&dns_config, &hostname)
            .map(|(dns, family)| (dns.clone(), family))
    };

    let dns_ips: Vec<String> = match ip_future.await {
        Some((dns, family)) => match dns.lookup(&hostname, family, None).await {
            Some(ip) => vec![ip],
            None => Vec::new(),
        },
        None => Vec::new(),
    };

    let tls_result = match dns_ips.first() {
        Some(ip) => crate::speed::tcp_ping(ip, 443, std::time::Duration::from_millis(3000)).await,
        None => None,
    };

    json!({
        "hostname": hostname,
        "dns": dns_ips,
        "tcp": dns_result,
        "tls": tls_result,
        "cost": start.elapsed().as_millis() as u64,
    })
}

#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command]
pub fn npm_get_registry() -> Value {
    let cfg = app::config().get();
    json!({
        "registry": crate::plugin::NodePlugin::registry(&cfg),
        "command": crate::plugin::NodePlugin::command(&cfg),
    })
}

#[tauri::command]
pub fn get_log_dir() -> String {
    paths::log_dir().to_string_lossy().to_string()
}
