//! 系统代理设置（对应原版 core/src/shell/scripts/set-system-proxy）

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct SysProxyParams {
    pub ip: String,
    /// HTTPS 端口（server.port）
    pub https_port: u16,
    /// HTTP 端口（server.port - 1）
    pub http_port: u16,
    pub proxy_http: bool,
    pub exclude_list: Vec<String>,
    pub set_env: bool,
    pub set_ca_bundle: bool,
    pub ca_cert_path: String,
}

#[allow(dead_code)]
const ENV_MARKER_BEGIN: &str = "# >>> dev-sidecar proxy env >>>";
#[allow(dead_code)]
const ENV_MARKER_END: &str = "# <<< dev-sidecar proxy env <<<";

/// 供插件调用：写入 HKCU 环境变量后广播刷新通知。
pub(crate) fn notify_env_changed() {
    #[cfg(target_os = "windows")]
    windows::notify_env_changed();
}

pub async fn setup_proxy(params: Option<SysProxyParams>) -> Result<()> {
    #[cfg(target_os = "windows")]
    return windows::set_system_proxy(params).await;
    #[cfg(target_os = "macos")]
    return macos::set_system_proxy(params).await;
    #[cfg(target_os = "linux")]
    return linux::set_system_proxy(params).await;
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = params;
        anyhow::bail!("当前平台不支持设置系统代理")
    }
}

/// 判断代理地址字符串是否指向本应用端口（纯函数，便于单测）。
/// 兼容多种写入格式：
/// - `127.0.0.1:31181`
/// - `http=127.0.0.1:31180;https=127.0.0.1:31181`
/// - `http://127.0.0.1:31181/`
#[allow(dead_code)]
pub(crate) fn proxy_server_is_local(value: &str, ports: &[u16]) -> bool {
    let v = value.trim().to_ascii_lowercase();
    // 本应用不会写入带认证信息的代理 URL；含 @ 的串可能是用户代理的
    // userinfo（例如 `http://127.0.0.1:31181@corp:8080`），不能误判。
    if v.is_empty() || v.contains('@') {
        return false;
    }
    let endpoint_at = |needle: &str| {
        let mut from = 0;
        while let Some(offset) = v[from..].find(needle) {
            let start = from + offset;
            let end = start + needle.len();
            let before = v[..start].chars().next_back();
            let after = v[end..].chars().next();
            let boundary = |c: Option<char>| {
                c.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-')
            };
            if boundary(before) && boundary(after) {
                return true;
            }
            from = end;
        }
        false
    };
    ports.iter().filter(|p| **p > 0).any(|port| {
        endpoint_at(&format!("127.0.0.1:{port}"))
            || endpoint_at(&format!("localhost:{port}"))
            || endpoint_at(&format!("[::1]:{port}"))
    })
}

/// 路径比较（忽略斜杠方向与大小写），用于判断 CA 证书路径类环境变量是否由本应用写入。
/// 注册表写入格式为正斜杠，配置中可能为反斜杠
#[allow(dead_code)]
pub(crate) fn is_same_path(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim().replace('\\', "/").to_ascii_lowercase();
    let (a, b) = (norm(a), norm(b));
    !a.is_empty() && a == b
}

/// 系统代理是否仍指向本应用（用于异常退出后的残留检测）。
/// 仅 Windows 有系统级代理注册表；macOS/Linux 的 profile 环境变量由 marker 块管理，无需检测
pub fn has_residual_proxy(https_port: u16, http_port: u16) -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::has_residual_proxy(https_port, http_port)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (https_port, http_port);
        false
    }
}

/// 关闭系统代理并清理本应用写入的环境变量（幂等，可重复调用）。
/// 与 `setup_proxy(None)` 的区别：携带配置上下文，环境变量按值匹配删除，避免误删用户自设代理
pub async fn teardown_proxy(params: SysProxyParams) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::teardown_proxy(params).await
    }
    #[cfg(target_os = "macos")]
    {
        let _ = params;
        macos::set_system_proxy(None).await
    }
    #[cfg(target_os = "linux")]
    {
        let _ = params;
        linux::set_system_proxy(None).await
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = params;
        anyhow::bail!("当前平台不支持设置系统代理")
    }
}

/// 拼接排除域名字符串
fn join_exclude(list: &[String], split: &str) -> String {
    list.iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect::<Vec<String>>()
        .join(split)
}

#[allow(dead_code)]
async fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let mut command = crate::util::hidden_tokio_command(cmd);
    command.args(args);
    let output = command.output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        anyhow::bail!("执行命令失败: {} {:?} -> {}", cmd, args, stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[allow(dead_code)]
async fn run_shell(cmd: &str) -> Result<String> {
    #[cfg(target_os = "windows")]
    return run("cmd", &["/C", cmd]).await;
    #[cfg(not(target_os = "windows"))]
    return run("sh", &["-c", cmd]).await;
}

// ------------------------------------------------------------------ Windows

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use crate::util::managed::{load_state, save_state, ManagedValue};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::path::Path;
    use winreg::enums::*;
    use winreg::RegKey;

    const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    #[derive(Debug, Default, Serialize, Deserialize)]
    struct ProxyState {
        version: u32,
        #[serde(default)]
        proxy_original: BTreeMap<String, ManagedValue>,
        #[serde(default)]
        proxy_written: BTreeMap<String, ManagedValue>,
        #[serde(default)]
        env_original: BTreeMap<String, ManagedValue>,
        #[serde(default)]
        env_written: BTreeMap<String, ManagedValue>,
    }

    fn state_path() -> std::path::PathBuf {
        crate::util::paths::sysproxy_managed_state_path()
    }

    fn open_key() -> Result<RegKey> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu.open_subkey_with_flags(INTERNET_SETTINGS, KEY_WRITE | KEY_READ)?;
        Ok(key)
    }

    fn refresh() {
        unsafe {
            use windows_sys::Win32::Networking::WinInet::InternetSetOptionW;
            // INTERNET_OPTION_SETTINGS_CHANGED = 39, INTERNET_OPTION_REFRESH = 37
            let _ = InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
            let _ = InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
        }
    }

    fn read_proxy_setting(key: &str) -> Result<ManagedValue> {
        let registry = open_key()?;
        if key == "ProxyEnable" {
            return match registry.get_value::<u32, _>(key) {
                Ok(v) => Ok(ManagedValue::Present(v.to_string())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ManagedValue::Absent),
                Err(e) => Err(anyhow::anyhow!("读取系统代理 {} 失败: {}", key, e)),
            };
        }
        match registry.get_value::<String, _>(key) {
            Ok(v) => Ok(ManagedValue::Present(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ManagedValue::Absent),
            Err(e) => Err(anyhow::anyhow!("读取系统代理 {} 失败: {}", key, e)),
        }
    }

    fn write_proxy_setting(key: &str, value: &ManagedValue) -> Result<()> {
        let registry = open_key()?;
        match value {
            ManagedValue::Present(v) if key == "ProxyEnable" => {
                let enabled: u32 = v
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("ProxyEnable 值非法: {}", v))?;
                registry.set_value(key, &enabled)?;
            }
            ManagedValue::Present(v) => registry.set_value(key, v)?,
            ManagedValue::Absent => match registry.delete_value(key) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(anyhow::anyhow!("删除系统代理 {} 失败: {}", key, e)),
            },
        }
        let actual = read_proxy_setting(key)?;
        if &actual != value {
            anyhow::bail!("系统代理 {} 写入后校验失败", key);
        }
        Ok(())
    }

    fn apply_proxy_setting(
        key: &str,
        desired: &ManagedValue,
        state: &mut ProxyState,
    ) -> Result<()> {
        let current = read_proxy_setting(key)?;
        let original = state
            .proxy_original
            .get(key)
            .cloned()
            .unwrap_or_else(|| current.clone());
        state
            .proxy_original
            .insert(key.to_string(), original.clone());
        if crate::util::managed::changed_externally(
            state.proxy_written.get(key),
            &current,
            &original,
            desired,
        ) {
            anyhow::bail!("系统代理 {} 已被外部程序修改，拒绝覆盖", key);
        }
        if &current != desired {
            write_proxy_setting(key, desired)?;
        }
        state.proxy_written.insert(key.to_string(), desired.clone());
        save_state(&state_path(), state)?;
        Ok(())
    }

    fn restore_proxy_settings(state: &mut ProxyState, only_if_written: bool) -> Result<()> {
        let mut errors = Vec::new();
        let keys: Vec<String> = state.proxy_original.keys().cloned().collect();
        for key in keys {
            let written = state.proxy_written.get(&key).cloned();
            let original = state
                .proxy_original
                .get(&key)
                .cloned()
                .unwrap_or(ManagedValue::Absent);
            let current = match read_proxy_setting(&key) {
                Ok(v) => v,
                Err(e) => {
                    errors.push(e.to_string());
                    continue;
                }
            };
            if current == original {
                state.proxy_written.remove(&key);
                continue;
            }
            let changed_externally = match (&written, &current) {
                (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
                (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
                (Some(_), _) => true,
                (None, _) => only_if_written,
            };
            if changed_externally {
                log_warn!("系统代理 {} 已被外部修改，保留当前值", key);
                state.proxy_written.remove(&key);
                continue;
            }
            if let Err(e) = write_proxy_setting(&key, &original) {
                errors.push(format!("{}: {}", key, e));
                continue;
            }
            state.proxy_written.remove(&key);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("恢复系统代理失败: {}", errors.join("; "))
        }
    }

    fn env_key() -> Result<RegKey> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey_with_flags("Environment", KEY_WRITE | KEY_READ)
            .map_err(|e| anyhow::anyhow!("打开 HKCU\\Environment 失败: {}", e))
    }

    fn read_env_var(key: &str) -> Option<String> {
        env_key().ok()?.get_value::<String, _>(key).ok()
    }

    fn read_env_managed(key: &str) -> ManagedValue {
        ManagedValue::from_option(read_env_var(key))
    }

    fn write_env_managed(key: &str, value: &ManagedValue) -> Result<()> {
        let environment = env_key()?;
        match value {
            ManagedValue::Present(v) => environment.set_value(key, &v.to_string())?,
            ManagedValue::Absent => match environment.delete_value(key) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(anyhow::anyhow!("删除环境变量 {} 失败: {}", key, e)),
            },
        }
        if read_env_managed(key) != *value {
            anyhow::bail!("环境变量 {} 写入后校验失败", key);
        }
        notify_env_changed();
        Ok(())
    }

    fn apply_env_var(key: &str, desired: &ManagedValue, state: &mut ProxyState) -> Result<()> {
        let current = read_env_managed(key);
        let original = state
            .env_original
            .get(key)
            .cloned()
            .unwrap_or_else(|| current.clone());
        state.env_original.insert(key.to_string(), original.clone());
        if crate::util::managed::changed_externally(
            state.env_written.get(key),
            &current,
            &original,
            desired,
        ) {
            anyhow::bail!("环境变量 {} 已被外部修改，拒绝覆盖", key);
        }
        if &current != desired {
            write_env_managed(key, desired)?;
        }
        state.env_written.insert(key.to_string(), desired.clone());
        save_state(&state_path(), state)?;
        Ok(())
    }

    fn restore_env_vars(state: &mut ProxyState, only_if_written: bool) -> Result<()> {
        let mut errors = Vec::new();
        let keys: Vec<String> = state.env_original.keys().cloned().collect();
        for key in keys {
            let written = state.env_written.get(&key).cloned();
            let original = state
                .env_original
                .get(&key)
                .cloned()
                .unwrap_or(ManagedValue::Absent);
            let current = read_env_managed(&key);
            if current == original {
                state.env_written.remove(&key);
                continue;
            }
            let changed_externally = match (&written, &current) {
                (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
                (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
                (Some(_), _) => true,
                (None, _) => only_if_written,
            };
            if changed_externally {
                log_warn!("环境变量 {} 已被外部修改，保留当前值", key);
                state.env_written.remove(&key);
                continue;
            }
            if let Err(e) = write_env_managed(&key, &original) {
                errors.push(format!("{}: {}", key, e));
                continue;
            }
            state.env_written.remove(&key);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("恢复代理环境变量失败: {}", errors.join("; "))
        }
    }

    /// 广播 WM_SETTINGCHANGE，让资源管理器刷新环境变量块。
    /// 已打开的终端仍会保留旧值，界面必须提示新终端才生效。
    pub(super) fn notify_env_changed() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
        };
        let lparam: Vec<u16> = "Environment\0".encode_utf16().collect();
        let mut result: usize = 0;
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                lparam.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                1000,
                &mut result,
            );
        }
    }

    fn desired_env_vars(p: &SysProxyParams) -> BTreeMap<String, ManagedValue> {
        let mut desired = BTreeMap::new();
        if p.set_env {
            let https_proxy = format!("http://{}:{}/", p.ip, p.https_port);
            desired.insert(
                "HTTPS_PROXY".into(),
                ManagedValue::Present(https_proxy.clone()),
            );
            desired.insert(
                "https_proxy".into(),
                ManagedValue::Present(https_proxy.clone()),
            );
            if p.proxy_http {
                let http_proxy = format!("http://{}:{}/", p.ip, p.http_port);
                desired.insert(
                    "HTTP_PROXY".into(),
                    ManagedValue::Present(http_proxy.clone()),
                );
                desired.insert(
                    "http_proxy".into(),
                    ManagedValue::Present(http_proxy.clone()),
                );
            }
            if p.set_ca_bundle && !p.ca_cert_path.is_empty() {
                let bundle = crate::util::paths::ca_bundle_path();
                match crate::tls::ensure_ca_bundle(Path::new(&p.ca_cert_path), &bundle) {
                    Ok(_) => {
                        let ca_value = bundle.to_string_lossy().to_string();
                        for key in ["REQUEST_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"] {
                            desired.insert(key.into(), ManagedValue::Present(ca_value.clone()));
                        }
                    }
                    Err(e) => {
                        // SSL_CERT_FILE / REQUEST_CA_BUNDLE 为替换语义，不能指向单一本地 CA；
                        // 失败时只保留追加语义的 NODE_EXTRA_CA_CERTS。
                        log_warn!(
                            "生成合并 CA bundle 失败，跳过 SSL_CERT_FILE 等替换语义变量: {}",
                            e
                        );
                        desired.insert(
                            "NODE_EXTRA_CA_CERTS".into(),
                            ManagedValue::Present(p.ca_cert_path.clone()),
                        );
                    }
                }
            }
            desired.insert(
                "NO_PROXY".into(),
                ManagedValue::Present(join_exclude(&p.exclude_list, ",")),
            );
            desired.insert(
                "no_proxy".into(),
                ManagedValue::Present(join_exclude(&p.exclude_list, ",")),
            );
        }
        desired
    }

    fn apply_env_vars(p: &SysProxyParams, state: &mut ProxyState) -> Result<()> {
        let desired = desired_env_vars(p);
        for (key, value) in &desired {
            apply_env_var(key, value, state)?;
        }
        // 本次不再需要的键只在当前值仍是上次写入值时恢复原始值
        let stale: Vec<String> = state
            .env_written
            .keys()
            .filter(|k| !desired.contains_key(*k))
            .cloned()
            .collect();
        for key in stale {
            let original = state
                .env_original
                .get(&key)
                .cloned()
                .unwrap_or(ManagedValue::Absent);
            let written = state.env_written.get(&key).cloned();
            let current = read_env_managed(&key);
            let changed_externally = match (&written, &current) {
                (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
                (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
                (Some(_), _) => true,
                (None, _) => true,
            };
            if changed_externally && current != original {
                log_warn!("环境变量 {} 已被外部修改，保留当前值", key);
                state.env_written.remove(&key);
                continue;
            }
            write_env_managed(&key, &original)?;
            state.env_written.remove(&key);
        }
        save_state(&state_path(), state)?;
        Ok(())
    }

    /// 系统代理是否仍指向本应用（ProxyEnable=1 且 ProxyServer 命中本应用端口）
    pub fn has_residual_proxy(https_port: u16, http_port: u16) -> bool {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok(key) = hkcu.open_subkey(INTERNET_SETTINGS) else {
            return false;
        };
        let enabled = key.get_value::<u32, _>("ProxyEnable").unwrap_or(0) != 0;
        if !enabled {
            return false;
        }
        let server = key
            .get_value::<String, _>("ProxyServer")
            .unwrap_or_default();
        proxy_server_is_local(&server, &[https_port, http_port])
    }

    /// 无快照时清系统代理：只有 ProxyServer 明确指向本应用才关闭，
    /// 绝不把用户原有代理/绕过列表覆盖成空值。
    fn legacy_cleanup_proxy(p: &SysProxyParams) {
        let Ok(server) = read_proxy_setting("ProxyServer") else {
            return;
        };
        let ManagedValue::Present(server) = server else {
            return;
        };
        if !proxy_server_is_local(&server, &[p.https_port, p.http_port]) {
            return;
        }
        let _ = write_proxy_setting("ProxyEnable", &ManagedValue::Present("0".into()));
        let _ = write_proxy_setting("ProxyServer", &ManagedValue::Absent);
        // ProxyOverride 保留原值：没有快照时无法判断用户自定义绕过列表，
        // 代理关闭后残留绕过项不会改变网络行为。
        refresh();
    }

    /// 旧版本没有快照时的兜底清理：仅删除明确指向本应用的值。
    async fn legacy_cleanup(p: &SysProxyParams) {
        let ports = [p.https_port, p.http_port];
        for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            if read_env_var(key).is_some_and(|v| proxy_server_is_local(&v, &ports)) {
                let _ = write_env_managed(key, &ManagedValue::Absent);
            }
        }
        if !p.ca_cert_path.is_empty() {
            let bundle = crate::util::paths::ca_bundle_path()
                .to_string_lossy()
                .to_string();
            for key in ["REQUEST_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"] {
                if read_env_var(key)
                    .is_some_and(|v| is_same_path(&v, &p.ca_cert_path) || is_same_path(&v, &bundle))
                {
                    let _ = write_env_managed(key, &ManagedValue::Absent);
                }
            }
        }
        let no_proxy = join_exclude(&p.exclude_list, ",");
        for key in ["NO_PROXY", "no_proxy"] {
            let owned = read_env_var(key).is_some_and(|v| {
                let v = v.trim();
                (!no_proxy.is_empty() && v == no_proxy) || v.contains("*.myapp.com")
            });
            if owned {
                let _ = write_env_managed(key, &ManagedValue::Absent);
            }
        }
    }

    /// 关闭系统代理：恢复接管前快照，不允许用空值覆盖用户原代理。
    pub async fn teardown_proxy(p: SysProxyParams) -> Result<()> {
        let path = state_path();
        let Some(mut state): Option<ProxyState> = load_state(&path)? else {
            log_warn!("未找到系统代理快照，仅清理明确指向本应用的兼容残留");
            legacy_cleanup_proxy(&p);
            legacy_cleanup(&p).await;
            return Ok(());
        };
        let proxy_result = restore_proxy_settings(&mut state, true);
        let env_result = restore_env_vars(&mut state, true);
        refresh();
        if proxy_result.is_err() || env_result.is_err() {
            save_state(&path, &state)?;
            let mut message = Vec::new();
            if let Err(e) = proxy_result {
                message.push(e.to_string());
            }
            if let Err(e) = env_result {
                message.push(e.to_string());
            }
            anyhow::bail!("关闭系统代理未完全恢复: {}", message.join("; "));
        }
        if state.proxy_written.is_empty() && state.env_written.is_empty() {
            let _ = std::fs::remove_file(path);
            log_info!("关闭 windows 系统代理成功，已恢复接管前配置");
        } else {
            save_state(&path, &state)?;
            log_warn!("部分系统代理配置已被外部修改，保留其当前值");
        }
        Ok(())
    }

    pub async fn set_system_proxy(params: Option<SysProxyParams>) -> Result<()> {
        let Some(p) = params else {
            // 无配置上下文时只恢复代理快照；环境变量需要 CA/端口信息，由 teardown_proxy 处理。
            let path = state_path();
            if let Some(mut state) = load_state::<ProxyState>(&path)? {
                restore_proxy_settings(&mut state, true)?;
                save_state(&path, &state)?;
            } else {
                // 没有端口上下文和快照时无法判断当前代理是否由本应用写入，
                // 保持原值并交给 teardown_proxy(cfg) 处理，避免误关用户代理。
                log_warn!("未找到系统代理快照且缺少端口信息，保持当前代理设置");
            }
            refresh();
            return Ok(());
        };

        let path = state_path();
        let mut state: ProxyState = load_state(&path)?.unwrap_or_default();
        if state.version == 0 {
            state.version = 1;
            save_state(&path, &state)?;
        }

        let proxy_addr = if p.proxy_http {
            format!(
                "http={}:{};https={}:{}",
                p.ip, p.http_port, p.ip, p.https_port
            )
        } else {
            format!("{}:{}", p.ip, p.https_port)
        };
        let exclude = join_exclude(&p.exclude_list, ";");
        let result = (|| -> Result<()> {
            apply_proxy_setting(
                "ProxyEnable",
                &ManagedValue::Present("1".into()),
                &mut state,
            )?;
            apply_proxy_setting(
                "ProxyServer",
                &ManagedValue::Present(proxy_addr.clone()),
                &mut state,
            )?;
            apply_proxy_setting(
                "ProxyOverride",
                &ManagedValue::Present(exclude.clone()),
                &mut state,
            )?;
            apply_env_vars(&p, &mut state)?;
            Ok(())
        })();

        refresh();
        if let Err(e) = result {
            let mut rollback_errors = Vec::new();
            if let Err(re) = restore_proxy_settings(&mut state, false) {
                rollback_errors.push(re.to_string());
            }
            if let Err(re) = restore_env_vars(&mut state, false) {
                rollback_errors.push(re.to_string());
            }
            if rollback_errors.is_empty() {
                let _ = std::fs::remove_file(&path);
                anyhow::bail!("设置系统代理失败，已恢复原配置: {}", e);
            }
            save_state(&path, &state)?;
            anyhow::bail!(
                "设置系统代理失败且回滚不完整: {}；残留: {}",
                e,
                rollback_errors.join("; ")
            );
        }

        save_state(&path, &state)?;
        log_info!(
            "设置 windows 系统代理成功: {} (排除列表 {} 项)",
            proxy_addr,
            p.exclude_list.len()
        );
        Ok(())
    }
}

// ------------------------------------------------------------------ macOS

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    async fn get_network_service() -> Result<String> {
        let output = run("networksetup", &["-listallnetworkservices"]).await?;
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('*') || line.starts_with("An asterisk") {
                continue;
            }
            return Ok(line.to_string());
        }
        anyhow::bail!("未找到可用的网络服务")
    }

    pub async fn set_system_proxy(params: Option<SysProxyParams>) -> Result<()> {
        let service = get_network_service().await?;
        match params {
            Some(p) => {
                let mut cmds = vec![format!(
                    "networksetup -setsecurewebproxy \"{}\" {} {}",
                    service, p.ip, p.https_port
                )];
                if p.proxy_http {
                    cmds.push(format!(
                        "networksetup -setwebproxy \"{}\" {} {}",
                        service, p.ip, p.http_port
                    ));
                    cmds.push(format!("networksetup -setwebproxystate \"{}\" on", service));
                } else {
                    cmds.push(format!(
                        "networksetup -setwebproxystate \"{}\" off",
                        service
                    ));
                }
                cmds.push(format!(
                    "networksetup -setsecurewebproxystate \"{}\" on",
                    service
                ));
                let exclude = join_exclude(&p.exclude_list, "\" \"");
                cmds.push(format!(
                    "networksetup -setproxybypassdomains \"{}\" \"{}\"",
                    service, exclude
                ));
                for cmd in &cmds {
                    if let Err(e) = run_shell(cmd).await {
                        log_warn!("执行命令失败: {} -> {}", cmd, e);
                    }
                }
                log_info!("设置 mac 系统代理成功: {}", service);
                write_proxy_env(&p).await;
            }
            None => {
                let cmds = [
                    format!("networksetup -setsecurewebproxystate \"{}\" off", service),
                    format!("networksetup -setwebproxystate \"{}\" off", service),
                ];
                for cmd in &cmds {
                    let _ = run_shell(cmd).await;
                }
                log_info!("关闭 mac 系统代理成功");
                remove_proxy_env().await;
            }
        }
        Ok(())
    }

    async fn write_proxy_env(p: &SysProxyParams) {
        if !p.set_env {
            return;
        }
        let mut lines = vec![ENV_MARKER_BEGIN.to_string()];
        lines.push(format!(
            "export HTTPS_PROXY=\"http://{}:{}\"",
            p.ip, p.https_port
        ));
        lines.push(format!(
            "export https_proxy=\"http://{}:{}\"",
            p.ip, p.https_port
        ));
        if p.proxy_http {
            lines.push(format!(
                "export HTTP_PROXY=\"http://{}:{}\"",
                p.ip, p.http_port
            ));
            lines.push(format!(
                "export http_proxy=\"http://{}:{}\"",
                p.ip, p.http_port
            ));
        }
        lines.push(format!(
            "export NO_PROXY=\"{}\"",
            join_exclude(&p.exclude_list, ",")
        ));
        if p.set_ca_bundle && !p.ca_cert_path.is_empty() {
            // NODE_EXTRA_CA_CERTS 为追加语义，始终安全
            lines.push(format!("export NODE_EXTRA_CA_CERTS=\"{}\"", p.ca_cert_path));
            if let Some(ca) = ca_env_value(p) {
                lines.push(format!("export REQUEST_CA_BUNDLE=\"{}\"", ca));
                lines.push(format!("export SSL_CERT_FILE=\"{}\"", ca));
            }
        }
        lines.push(ENV_MARKER_END.to_string());
        let _ = append_profile(lines.join("\n")).await;
    }
}

// ------------------------------------------------------------------ Linux

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub async fn set_system_proxy(params: Option<SysProxyParams>) -> Result<()> {
        match params {
            Some(p) => {
                let mut cmds = vec![
                    "gsettings set org.gnome.system.proxy mode manual".to_string(),
                    format!("gsettings set org.gnome.system.proxy.https host {}", p.ip),
                    format!(
                        "gsettings set org.gnome.system.proxy.https port {}",
                        p.https_port
                    ),
                ];
                if p.proxy_http {
                    cmds.push(format!(
                        "gsettings set org.gnome.system.proxy.http host {}",
                        p.ip
                    ));
                    cmds.push(format!(
                        "gsettings set org.gnome.system.proxy.http port {}",
                        p.http_port
                    ));
                } else {
                    cmds.push("gsettings set org.gnome.system.proxy.http host ''".to_string());
                    cmds.push("gsettings set org.gnome.system.proxy.http port 0".to_string());
                }
                let exclude = join_exclude(&p.exclude_list, "', '");
                cmds.push(format!(
                    "gsettings set org.gnome.system.proxy ignore-hosts \"['{}']\"",
                    exclude
                ));
                for cmd in &cmds {
                    if let Err(e) = run_shell(cmd).await {
                        log_warn!("gsettings 设置失败（可能无桌面环境）: {} -> {}", cmd, e);
                        break;
                    }
                }
                log_info!("设置 linux 系统代理成功");

                if p.set_env {
                    let mut lines = vec![ENV_MARKER_BEGIN.to_string()];
                    lines.push(format!(
                        "export HTTPS_PROXY=\"http://{}:{}\"",
                        p.ip, p.https_port
                    ));
                    lines.push(format!(
                        "export https_proxy=\"http://{}:{}\"",
                        p.ip, p.https_port
                    ));
                    if p.proxy_http {
                        lines.push(format!(
                            "export HTTP_PROXY=\"http://{}:{}\"",
                            p.ip, p.http_port
                        ));
                        lines.push(format!(
                            "export http_proxy=\"http://{}:{}\"",
                            p.ip, p.http_port
                        ));
                    }
                    lines.push(format!(
                        "export NO_PROXY=\"{}\"",
                        join_exclude(&p.exclude_list, ",")
                    ));
                    if p.set_ca_bundle && !p.ca_cert_path.is_empty() {
                        lines.push(format!("export NODE_EXTRA_CA_CERTS=\"{}\"", p.ca_cert_path));
                        if let Some(ca) = ca_env_value(p) {
                            lines.push(format!("export REQUEST_CA_BUNDLE=\"{}\"", ca));
                            lines.push(format!("export SSL_CERT_FILE=\"{}\"", ca));
                        }
                    }
                    lines.push(ENV_MARKER_END.to_string());
                    let _ = append_profile(lines.join("\n")).await;
                }
            }
            None => {
                let _ = run_shell("gsettings set org.gnome.system.proxy mode none").await;
                log_info!("关闭 linux 系统代理成功");
                let _ = remove_profile_block().await;
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
async fn remove_proxy_env() {
    let _ = remove_profile_block().await;
}

/// 合并 CA bundle 路径：供「替换」语义的 CA 环境变量（SSL_CERT_FILE 等）使用。
/// 生成失败时返回 None —— 此时不能把替换语义变量指向单一本地 CA
#[cfg(not(target_os = "windows"))]
fn ca_env_value(p: &SysProxyParams) -> Option<String> {
    let bundle = crate::util::paths::ca_bundle_path();
    match crate::tls::ensure_ca_bundle(std::path::Path::new(&p.ca_cert_path), &bundle) {
        Ok(_) => Some(bundle.to_string_lossy().to_string()),
        Err(e) => {
            log_warn!("生成合并 CA bundle 失败，跳过替换语义的 CA 环境变量: {}", e);
            None
        }
    }
}

/// 向 shell profile 追加（若已存在则先移除）
#[cfg(not(target_os = "windows"))]
async fn append_profile(block: String) -> Result<()> {
    let home = dirs::home_dir().unwrap_or_default();
    for name in [".profile", ".bashrc", ".zshrc"] {
        let path = home.join(name);
        if !path.exists() {
            continue;
        }
        let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        let cleaned = remove_block(&content);
        let mut new_content = cleaned.trim_end().to_string();
        new_content.push_str(&format!("\n{}\n", block));
        let _ = tokio::fs::write(&path, new_content).await;
        log_info!("已写入代理环境变量到 {}", path.display());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn remove_profile_block() -> Result<()> {
    let home = dirs::home_dir().unwrap_or_default();
    for name in [".profile", ".bashrc", ".zshrc"] {
        let path = home.join(name);
        if !path.exists() {
            continue;
        }
        let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        let cleaned = remove_block(&content);
        if cleaned != content {
            let _ = tokio::fs::write(&path, cleaned).await;
            log_info!("已从 {} 移除代理环境变量", path.display());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn remove_block(content: &str) -> String {
    match (content.find(ENV_MARKER_BEGIN), content.find(ENV_MARKER_END)) {
        (Some(begin), Some(end)) if end > begin => {
            let stop = end + ENV_MARKER_END.len();
            let stop = content[stop..]
                .find('\n')
                .map(|i| stop + i + 1)
                .unwrap_or(stop);
            format!("{}{}", &content[..begin], &content[stop..])
        }
        _ => content.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORTS: [u16; 2] = [31181, 31180];

    /// 简写格式：127.0.0.1:31181
    #[test]
    fn local_proxy_plain_format() {
        assert!(proxy_server_is_local("127.0.0.1:31181", &PORTS));
        assert!(proxy_server_is_local("127.0.0.1:31180", &PORTS));
    }

    /// 双端口格式：http=...;https=...
    #[test]
    fn local_proxy_protocol_format() {
        assert!(proxy_server_is_local(
            "http=127.0.0.1:31180;https=127.0.0.1:31181",
            &PORTS
        ));
        // 仅 HTTP 段命中
        assert!(proxy_server_is_local(
            "http=127.0.0.1:31180;https=1.1.1.1:443",
            &PORTS
        ));
    }

    /// URL 格式（环境变量里常见）
    #[test]
    fn local_proxy_url_format() {
        assert!(proxy_server_is_local("http://127.0.0.1:31181/", &PORTS));
        assert!(proxy_server_is_local("HTTP://LOCALHOST:31180", &PORTS));
        assert!(proxy_server_is_local("http://[::1]:31181/", &PORTS));
    }

    /// 非本应用端口或非本机地址不应命中（避免误判导致误清理）
    #[test]
    fn non_local_proxy_not_matched() {
        assert!(!proxy_server_is_local("127.0.0.1:7890", &PORTS));
        assert!(!proxy_server_is_local("192.168.1.10:31181", &PORTS));
        assert!(!proxy_server_is_local("proxy.company.com:8080", &PORTS));
        assert!(!proxy_server_is_local("", &PORTS));
        // 端口 0 视为无效，不参与匹配
        assert!(!proxy_server_is_local("127.0.0.1:0", &[0, 0]));
        // 端口前缀相同（311810）或作为 userinfo/域名一部分时不能误清理
        assert!(!proxy_server_is_local("127.0.0.1:311810", &PORTS));
        assert!(!proxy_server_is_local(
            "http://127.0.0.1:31181@corp-proxy:8080",
            &PORTS
        ));
        assert!(!proxy_server_is_local(
            "127.0.0.1:31181.example.com:80",
            &PORTS
        ));
        assert!(proxy_server_is_local("http://127.0.0.1:31181", &PORTS));
    }

    /// CA 路径比较忽略斜杠方向与大小写
    #[test]
    fn ca_path_compare_normalizes_slashes() {
        assert!(is_same_path(
            "C:/Users/hostel/.dev-sidecar/dev-sidecar.ca.crt",
            r"C:\Users\hostel\.dev-sidecar\dev-sidecar.ca.crt"
        ));
        assert!(is_same_path("c:/users/a/b.crt", "C:/Users/A/B.CRT"));
        assert!(!is_same_path(
            "C:/Users/hostel/.dev-sidecar/dev-sidecar.ca.crt",
            "C:/Users/hostel/.dev-sidecar/other.crt"
        ));
        assert!(!is_same_path("", "C:/x.crt"));
    }

    /// NO_PROXY 预期串：以当前配置的排除列表为准，保证写入与清理判定一致
    #[test]
    fn no_proxy_expected_string() {
        let list = vec![
            "*.cn".to_string(),
            "  localhost  ".to_string(), // 首尾空白应被裁剪
            String::new(),               // 空项应被忽略
        ];
        assert_eq!(join_exclude(&list, ","), "*.cn,localhost");
        assert_eq!(join_exclude(&list, ";"), "*.cn;localhost");
    }
}
