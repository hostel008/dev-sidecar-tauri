//! Git / NPM / PIP 加速插件（对应原版 core/src/modules/plugin）

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::process::Stdio;

/// 受检命令输出。关键写入不能依赖“命令启动了”判断成功，必须同时检查退出码。
struct CommandOutput {
    success: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

async fn run_command(cmd: &str, args: &[&str]) -> Result<CommandOutput> {
    let spawn = |program: &str| {
        let mut command = crate::util::hidden_tokio_command(program);
        command.args(args).stdin(Stdio::null());
        command
    };
    let mut output = spawn(cmd).output().await;
    // Windows 上 npm 等命令常以 .cmd 脚本形式存在，CreateProcess 只搜索 .exe，失败时回退到 .cmd
    #[cfg(target_os = "windows")]
    if let Err(e) = &output {
        if e.kind() == std::io::ErrorKind::NotFound
            && !cmd.contains('/')
            && !cmd.contains('\\')
            && !cmd.to_lowercase().ends_with(".exe")
        {
            let cmd_script = format!("{}.cmd", cmd);
            output = spawn(&cmd_script).output().await;
        }
    }
    let out = output.map_err(|e| anyhow::anyhow!("执行 {} 失败: {}", cmd, e))?;
    Ok(CommandOutput {
        success: out.status.success(),
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

/// 执行并检查退出状态；错误信息只包含截断后的 stderr，避免把命令参数中的
/// 自定义 token/代理凭据写入日志。
async fn exec_checked(cmd: &str, args: &[&str]) -> Result<String> {
    let out = run_command(cmd, args).await?;
    if !out.success {
        let detail = out.stderr.trim();
        let detail: String = detail.chars().take(500).collect();
        anyhow::bail!("命令执行失败（退出码非零）{}: {}", cmd, detail);
    }
    Ok(out.stdout)
}

/// 受检执行 npm user 配置命令。显式 --location=user，避免受项目 .npmrc 影响。
async fn npm_user(cmd: &str, action: &str, pairs: &[(&str, &str)]) -> Result<String> {
    let mut args: Vec<&str> = vec!["config", action];
    for (k, v) in pairs {
        if action == "set" {
            args.push(k);
            args.push(v);
        } else {
            args.push(k);
        }
    }
    args.push("--location=user");
    exec_checked(cmd, &args).await
}

fn as_bool(v: Option<&Value>, default: bool) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0) > 0.0,
        _ => default,
    }
}

// ------------------------------------------------------------------ NPM

const NPM_FIXED_KEYS: [&str; 5] = ["registry", "strict-ssl", "cafile", "proxy", "https-proxy"];

/// NPM 插件的事务状态。`original` 在第一次接管前生成，`written` 是本应用
/// 最近一次写入的值。关闭/恢复时只有当前值仍等于 `written` 才回写 original，
/// 用户或其他工具后来改过的值不会被覆盖。
#[derive(Debug, Serialize, Deserialize, Default)]
struct NpmManagedState {
    version: u32,
    command: String,
    userconfig: String,
    #[serde(default)]
    npm_original: BTreeMap<String, ManagedValue>,
    #[serde(default)]
    npm_written: BTreeMap<String, ManagedValue>,
    #[serde(default)]
    env_original: BTreeMap<String, ManagedValue>,
    #[serde(default)]
    env_written: BTreeMap<String, ManagedValue>,
}

use crate::util::managed::{load_state, save_state, ManagedValue};

fn npm_state_path() -> std::path::PathBuf {
    crate::util::paths::npm_managed_state_path()
}

fn parse_npmrc_value(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return Some(String::new());
    }
    if let Some(inner) = raw.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        return Some(unescape_ini_value(inner));
    }
    if let Some(inner) = raw.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        return Some(inner.to_string());
    }
    // npm ini 允许未加引号的值；实测 `npm config set` 写入 Windows 路径时既不
    // 加引号也不转义（`cafile=C:\tools\ca.pem`），此时必须原样返回，不能把
    // `\t` / `\n` 当成转义序列，否则读回校验会失败。
    Some(raw.to_string())
}

/// 反转 ini 双引号值的转义。必须单遍扫描：`\\tools` 表示“反斜杠 + tools”，
/// 逐段 replace 会先命中 `\\` 之后的 `\t`，把 Windows 路径改坏。
fn unescape_ini_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            // 未识别的转义按字面保留，避免吞掉路径里的字符
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// 直接读取用户 .npmrc，而不是 `npm config get`，因为后者会返回内置默认值，
/// 无法区分“用户原本未设置”和“用户显式设置成默认值”。
fn read_npmrc_value(userconfig: &str, key: &str) -> Result<ManagedValue> {
    let path = std::path::Path::new(userconfig);
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ManagedValue::Absent);
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "读取 npm 配置失败 {}: {}",
                path.display(),
                e
            ))
        }
    };
    let mut found: Option<String> = None;
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        if raw_key.trim().eq_ignore_ascii_case(key) {
            found = parse_npmrc_value(Some(raw_value));
        }
    }
    Ok(ManagedValue::from_option(found))
}

async fn npm_userconfig(cmd: &str) -> Result<String> {
    let out = exec_checked(cmd, &["config", "get", "userconfig", "--location=user"]).await?;
    let path = out.trim().trim_matches('"');
    if path.is_empty() || path == "null" || path == "undefined" {
        anyhow::bail!("npm 未返回可用的 userconfig 路径");
    }
    Ok(path.to_string())
}

async fn set_npm_key(cmd: &str, userconfig: &str, key: &str, value: &ManagedValue) -> Result<()> {
    match value {
        ManagedValue::Present(v) => {
            npm_user(cmd, "set", &[(key, v)]).await?;
        }
        ManagedValue::Absent => {
            // delete 对不存在的键在部分 npm 版本会返回非零；先读取，已不存在即成功。
            if read_npmrc_value(userconfig, key)? == ManagedValue::Absent {
                return Ok(());
            }
            npm_user(cmd, "delete", &[(key, "")]).await?;
        }
    }
    Ok(())
}

async fn verify_npm_key(userconfig: &str, key: &str, expected: &ManagedValue) -> Result<()> {
    let actual = read_npmrc_value(userconfig, key)?;
    if &actual != expected {
        anyhow::bail!(
            "npm 配置写入后校验失败: {} 期望 {:?}，实际 {:?}",
            key,
            expected,
            actual
        );
    }
    Ok(())
}

async fn apply_npm_keys(
    cmd: &str,
    userconfig: &str,
    state: &mut NpmManagedState,
    desired: &BTreeMap<String, ManagedValue>,
    expected_now: &mut BTreeMap<String, ManagedValue>,
) -> Result<()> {
    for (key, value) in desired {
        let current = read_npmrc_value(userconfig, key)?;
        let original = state
            .npm_original
            .get(key)
            .cloned()
            .unwrap_or_else(|| current.clone());
        state.npm_original.insert(key.clone(), original.clone());
        if crate::util::managed::changed_externally(
            state.npm_written.get(key),
            &current,
            &original,
            value,
        ) {
            anyhow::bail!(
                "npm 配置 {} 已被外部修改，拒绝覆盖；请先处理该配置后重试",
                key
            );
        }
        if &current != value {
            set_npm_key(cmd, userconfig, key, value).await?;
            verify_npm_key(userconfig, key, value).await?;
        }
        expected_now.insert(key.clone(), value.clone());
        state.npm_written.insert(key.clone(), value.clone());
        save_state(&npm_state_path(), state)?;
    }
    Ok(())
}

async fn restore_npm_keys(
    cmd: &str,
    userconfig: &str,
    state: &mut NpmManagedState,
    only_if_written: bool,
) -> Result<()> {
    let mut errors = Vec::new();
    let keys: Vec<String> = state.npm_original.keys().cloned().collect();
    for key in keys {
        let original = state
            .npm_original
            .get(&key)
            .cloned()
            .unwrap_or(ManagedValue::Absent);
        let written = state.npm_written.get(&key).cloned();
        let current = match read_npmrc_value(userconfig, &key) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("{}: {}", key, e));
                continue;
            }
        };
        if current == original {
            state.npm_written.remove(&key);
            continue;
        }
        let changed_externally = match (&written, &current) {
            (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
            (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
            (Some(_), _) => true,
            (None, _) => only_if_written,
        };
        if changed_externally {
            log_warn!("npm 配置 {} 已被外部修改，保留当前值并停止托管", key);
            state.npm_written.remove(&key);
            continue;
        }
        if let Err(e) = set_npm_key(cmd, userconfig, &key, &original).await {
            errors.push(format!("{}: {}", key, e));
            continue;
        }
        if let Err(e) = verify_npm_key(userconfig, &key, &original).await {
            errors.push(format!("{}: {}", key, e));
            continue;
        }
        state.npm_written.remove(&key);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("恢复 npm 配置失败: {}", errors.join("; "))
    }
}

fn node_env_desired(
    config: &Value,
    use_cafile: bool,
    ca_path: &str,
) -> BTreeMap<String, ManagedValue> {
    let mut desired = BTreeMap::new();
    if let Some(Value::Object(envs)) = config.pointer("/plugin/node/envVariables") {
        for (k, v) in envs {
            if let Some(value) = v.as_str() {
                desired.insert(k.clone(), ManagedValue::Present(value.to_string()));
            }
        }
    }
    if use_cafile && !ca_path.is_empty() {
        desired.insert(
            "NODE_EXTRA_CA_CERTS".to_string(),
            ManagedValue::Present(ca_path.to_string()),
        );
    }
    desired
}

async fn apply_env_keys(
    state: &mut NpmManagedState,
    desired: &BTreeMap<String, ManagedValue>,
    expected_now: &mut BTreeMap<String, ManagedValue>,
) -> Result<()> {
    for (key, value) in desired {
        let current = ManagedValue::from_option(user_env_value(key));
        let original = state
            .env_original
            .get(key)
            .cloned()
            .unwrap_or_else(|| current.clone());
        state.env_original.insert(key.clone(), original.clone());
        if crate::util::managed::changed_externally(
            state.env_written.get(key),
            &current,
            &original,
            value,
        ) {
            anyhow::bail!("环境变量 {} 已被外部修改，拒绝覆盖", key);
        }
        if &current != value {
            match value {
                ManagedValue::Present(v) => write_user_env_checked(key, v).await?,
                ManagedValue::Absent => delete_user_env_checked(key).await?,
            }
        }
        expected_now.insert(key.clone(), value.clone());
        state.env_written.insert(key.clone(), value.clone());
        save_state(&npm_state_path(), state)?;
    }
    Ok(())
}

async fn restore_env_keys(state: &mut NpmManagedState, only_if_written: bool) -> Result<()> {
    let mut errors = Vec::new();
    let keys: Vec<String> = state.env_original.keys().cloned().collect();
    for key in keys {
        let original = state
            .env_original
            .get(&key)
            .cloned()
            .unwrap_or(ManagedValue::Absent);
        let written = state.env_written.get(&key).cloned();
        let current = ManagedValue::from_option(user_env_value(&key));
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
        let result = match &original {
            ManagedValue::Present(v) => write_user_env_checked(&key, v).await,
            ManagedValue::Absent => delete_user_env_checked(&key).await,
        };
        if let Err(e) = result {
            errors.push(format!("{}: {}", key, e));
            continue;
        }
        state.env_written.remove(&key);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("恢复环境变量失败: {}", errors.join("; "))
    }
}

/// 崩溃残留恢复：仅回滚当前值仍等于本应用最后一次写入值的键。
pub async fn recover_npm_state(config: &Value) -> Result<()> {
    let path = npm_state_path();
    let Some(mut state): Option<NpmManagedState> = load_state(&path)? else {
        return Ok(());
    };
    if state.npm_written.is_empty() && state.env_written.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let cmd = NodePlugin::command(config);
    let userconfig = if state.userconfig.is_empty() {
        npm_userconfig(&cmd).await?
    } else {
        state.userconfig.clone()
    };
    let mut errors = Vec::new();
    if let Err(e) = restore_npm_keys(&cmd, &userconfig, &mut state, true).await {
        errors.push(e.to_string());
    }
    if let Err(e) = restore_env_keys(&mut state, true).await {
        errors.push(e.to_string());
    }
    if errors.is_empty() {
        if state.npm_written.is_empty() && state.env_written.is_empty() {
            let _ = std::fs::remove_file(&path);
        } else {
            save_state(&path, &state)?;
        }
        Ok(())
    } else {
        save_state(&path, &state)?;
        anyhow::bail!("恢复 NPM 残留配置不完整: {}", errors.join("; "))
    }
}

pub struct NodePlugin;

impl NodePlugin {
    pub fn registry(config: &Value) -> String {
        config
            .pointer("/plugin/node/setting/registry")
            .and_then(|v| v.as_str())
            .unwrap_or("https://registry.npmjs.org")
            .to_string()
    }

    pub fn command(config: &Value) -> String {
        config
            .pointer("/plugin/node/setting/command")
            .and_then(|v| v.as_str())
            .unwrap_or("npm")
            .to_string()
    }

    pub fn local_registry() -> Result<String> {
        let reg = Self::registry(&crate::app::config().get());
        Ok(reg)
    }

    pub async fn open_proxy(config: &Value, ip: &str, port: u16) -> Result<()> {
        let cmd = Self::command(config);
        let userconfig = npm_userconfig(&cmd).await?;
        let registry = Self::registry(config);
        let strict_ssl = as_bool(config.pointer("/plugin/node/setting/strict-ssl"), true);
        let cafile_enabled = as_bool(config.pointer("/plugin/node/setting/cafile"), false);
        let extra_ca_enabled = as_bool(
            config.pointer("/plugin/node/setting/NODE_EXTRA_CA_CERTS"),
            false,
        );
        let ca_path = config
            .pointer("/server/setting/rootCaFile/certPath")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // cafile 是「替换 npm/Node 默认信任库」语义，必须指向合并 bundle；
        // 绝不能只指向 DevSidecar CA，否则未走 MITM 的公共站点会证书校验失败。
        let mut cafile_bundle: Option<String> = None;
        if cafile_enabled {
            if ca_path.is_empty() {
                anyhow::bail!("已启用 npm cafile，但 DevSidecar CA 路径为空");
            }
            let bundle = crate::util::paths::ca_bundle_path();
            crate::tls::ensure_ca_bundle(std::path::Path::new(&ca_path), &bundle)?;
            cafile_bundle = Some(bundle.to_string_lossy().to_string());
        }
        if extra_ca_enabled && ca_path.is_empty() {
            anyhow::bail!("已启用 NODE_EXTRA_CA_CERTS，但 DevSidecar CA 路径为空");
        }

        let mut state: NpmManagedState = load_state(&npm_state_path())?.unwrap_or_default();
        if state.userconfig.is_empty() {
            state.version = 1;
            state.command = cmd.clone();
            state.userconfig = userconfig.clone();
            // 先落盘“尚未写入任何键”的原始状态，再开始首个写操作。
            save_state(&npm_state_path(), &state)?;
        } else if !crate::sysproxy::is_same_path(&state.userconfig, &userconfig) {
            anyhow::bail!(
                "npm userconfig 与上次接管时不一致（上次 {}，当前 {}）；请先修复残留配置",
                state.userconfig,
                userconfig
            );
        } else {
            state.command = cmd.clone();
        }

        let proxy_url = format!("http://{}:{}", ip, port);
        // `cafile` 不参与默认接管：用户可能已经用它信任公司根证书，
        // 关闭本插件的 cafile 选项只代表“不替换信任库”，绝不等于删除用户配置。
        // 关闭时若上一轮由本应用写入过，下面的 stale 分支会按快照恢复原值。
        let mut desired_npm: BTreeMap<String, ManagedValue> = NPM_FIXED_KEYS
            .iter()
            .filter(|k| **k != "cafile")
            .map(|k| (k.to_string(), ManagedValue::Absent))
            .collect();
        desired_npm.insert("registry".into(), ManagedValue::Present(registry.clone()));
        desired_npm.insert(
            "strict-ssl".into(),
            ManagedValue::Present(if strict_ssl { "true" } else { "false" }.into()),
        );
        desired_npm.insert("proxy".into(), ManagedValue::Present(proxy_url.clone()));
        desired_npm.insert(
            "https-proxy".into(),
            ManagedValue::Present(proxy_url.clone()),
        );
        if let Some(bundle) = &cafile_bundle {
            desired_npm.insert("cafile".into(), ManagedValue::Present(bundle.clone()));
        }
        if let Some(Value::Object(vars)) = config.pointer("/plugin/node/variables") {
            for (k, v) in vars {
                if let Some(value) = v.as_str() {
                    desired_npm.insert(k.clone(), ManagedValue::Present(value.to_string()));
                }
            }
        }
        let desired_env = node_env_desired(config, extra_ca_enabled, &ca_path);

        let mut expected_npm = BTreeMap::new();
        let mut expected_env = BTreeMap::new();
        let result: Result<()> = async {
            apply_npm_keys(
                &cmd,
                &userconfig,
                &mut state,
                &desired_npm,
                &mut expected_npm,
            )
            .await?;
            // 之前写过、本次期望不存在的键先恢复原始值（例如关闭 cafile）。
            // 只有当前值仍是我们上次写入的值才能回退，否则用户/其他工具已改过，
            // 再写 original 会把用户的改动覆盖掉。
            let stale: Vec<String> = state
                .npm_written
                .keys()
                .filter(|k| !desired_npm.contains_key(*k))
                .cloned()
                .collect();
            for key in stale {
                let current = read_npmrc_value(&userconfig, &key)?;
                let Some(original) = state.npm_original.get(&key).cloned() else {
                    state.npm_written.remove(&key);
                    continue;
                };
                if crate::util::managed::changed_externally(
                    state.npm_written.get(&key),
                    &current,
                    &original,
                    &original,
                ) {
                    log_warn!("npm 配置 {} 已被外部修改，保留当前值并停止托管", key);
                    state.npm_written.remove(&key);
                    continue;
                }
                set_npm_key(&cmd, &userconfig, &key, &original).await?;
                verify_npm_key(&userconfig, &key, &original).await?;
                state.npm_written.remove(&key);
            }
            apply_env_keys(&mut state, &desired_env, &mut expected_env).await?;
            let stale_env: Vec<String> = state
                .env_written
                .keys()
                .filter(|k| !desired_env.contains_key(*k))
                .cloned()
                .collect();
            for key in stale_env {
                let Some(original) = state.env_original.get(&key).cloned() else {
                    state.env_written.remove(&key);
                    continue;
                };
                let current = ManagedValue::from_option(user_env_value(&key));
                if crate::util::managed::changed_externally(
                    state.env_written.get(&key),
                    &current,
                    &original,
                    &original,
                ) {
                    log_warn!("环境变量 {} 已被外部修改，保留当前值", key);
                    state.env_written.remove(&key);
                    continue;
                }
                match &original {
                    ManagedValue::Present(v) => write_user_env_checked(&key, v).await?,
                    ManagedValue::Absent => delete_user_env_checked(&key).await?,
                }
                state.env_written.remove(&key);
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            // 回滚本次仍由我们持有的值。若回滚也失败，保留状态文件供“修复残留配置”使用。
            let mut rollback_errors = Vec::new();
            for (key, value) in &expected_npm {
                let current = read_npmrc_value(&userconfig, key).unwrap_or(ManagedValue::Absent);
                if &current == value {
                    let original = state
                        .npm_original
                        .get(key)
                        .cloned()
                        .unwrap_or(ManagedValue::Absent);
                    if let Err(re) = set_npm_key(&cmd, &userconfig, key, &original).await {
                        rollback_errors.push(format!("{}: {}", key, re));
                    } else {
                        state.npm_written.remove(key);
                    }
                }
            }
            for (key, value) in &expected_env {
                if &ManagedValue::from_option(user_env_value(key)) == value {
                    let original = state
                        .env_original
                        .get(key)
                        .cloned()
                        .unwrap_or(ManagedValue::Absent);
                    let re = match &original {
                        ManagedValue::Present(v) => write_user_env_checked(key, v).await,
                        ManagedValue::Absent => delete_user_env_checked(key).await,
                    };
                    if let Err(re) = re {
                        rollback_errors.push(format!("{}: {}", key, re));
                    } else {
                        state.env_written.remove(key);
                    }
                }
            }
            if rollback_errors.is_empty() {
                let _ = std::fs::remove_file(npm_state_path());
                anyhow::bail!("NPM 加速开启失败，已回滚: {}", e);
            }
            save_state(&npm_state_path(), &state)?;
            anyhow::bail!(
                "NPM 加速开启失败且回滚不完整: {}；残留: {}",
                e,
                rollback_errors.join("; ")
            );
        }

        save_state(&npm_state_path(), &state)?;
        log_info!(
            "NPM 加速已开启，registry: {}，userconfig: {}",
            registry,
            userconfig
        );
        Ok(())
    }

    pub async fn close_proxy(config: &Value) -> Result<()> {
        let path = npm_state_path();
        let Some(mut state): Option<NpmManagedState> = load_state(&path)? else {
            // 旧版本没有状态文件：只清理明确指向本应用的死引用，不删除 registry
            // 与用户可能自行设置的 strict-ssl。
            return Self::legacy_cleanup(config).await;
        };
        let cmd = Self::command(config);
        let userconfig = state.userconfig.clone();
        if userconfig.is_empty() {
            anyhow::bail!("NPM 托管状态缺少 userconfig，无法恢复");
        }
        let npm_result = restore_npm_keys(&cmd, &userconfig, &mut state, true).await;
        let env_result = restore_env_keys(&mut state, true).await;
        if npm_result.is_err() || env_result.is_err() {
            save_state(&path, &state)?;
            let mut message = Vec::new();
            if let Err(e) = npm_result {
                message.push(e.to_string());
            }
            if let Err(e) = env_result {
                message.push(e.to_string());
            }
            anyhow::bail!("NPM 加速关闭未完全恢复: {}", message.join("; "));
        }
        if state.npm_written.is_empty() && state.env_written.is_empty() {
            let _ = std::fs::remove_file(path);
        } else {
            save_state(&path, &state)?;
        }
        log_info!("NPM 加速已关闭，用户原配置已恢复");
        Ok(())
    }

    /// 兼容旧版无快照状态：仅删除指向本应用端口/CA 的配置。
    /// 清理失败必须向上报告，否则界面会显示“已关闭”而 npm 仍信任死引用。
    async fn legacy_cleanup(config: &Value) -> Result<()> {
        let cmd = Self::command(config);
        let ca_path = config
            .pointer("/server/setting/rootCaFile/certPath")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut errors = Vec::new();
        if let Ok(userconfig) = npm_userconfig(&cmd).await {
            for key in ["proxy", "https-proxy"] {
                if let Ok(ManagedValue::Present(value)) = read_npmrc_value(&userconfig, key) {
                    if let Ok(url) = url::Url::parse(&value) {
                        if url.host_str() == Some("127.0.0.1")
                            || url.host_str() == Some("localhost")
                        {
                            if let Err(e) = npm_user(&cmd, "delete", &[(key, "")]).await {
                                errors.push(format!("npm {}: {}", key, e));
                            }
                        }
                    }
                }
            }
            // 旧版本可能把 cafile 指向只含本应用 CA 的文件，这是会破坏公共站点的残留。
            if !ca_path.is_empty() {
                if let Ok(ManagedValue::Present(value)) = read_npmrc_value(&userconfig, "cafile") {
                    let bundle = crate::util::paths::ca_bundle_path()
                        .to_string_lossy()
                        .to_string();
                    if crate::sysproxy::is_same_path(&value, ca_path)
                        || crate::sysproxy::is_same_path(&value, &bundle)
                    {
                        if let Err(e) = npm_user(&cmd, "delete", &[("cafile", "")]).await {
                            errors.push(format!("npm cafile: {}", e));
                        }
                    }
                }
            }
        }
        if let Err(e) = remove_user_env_if_path("NODE_EXTRA_CA_CERTS", ca_path).await {
            errors.push(format!("NODE_EXTRA_CA_CERTS: {}", e));
        }
        if let Some(Value::Object(envs)) = config.pointer("/plugin/node/envVariables") {
            for (k, v) in envs {
                if let Some(value) = v.as_str() {
                    if user_env_value(k).is_some_and(|current| current == value) {
                        if let Err(e) = delete_user_env_checked(k).await {
                            errors.push(format!("{}: {}", k, e));
                        }
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("NPM 兼容清理未完全完成: {}", errors.join("; "))
        }
    }
}

// ------------------------------------------------------------------ Git

fn git_state_path() -> std::path::PathBuf {
    crate::util::paths::git_managed_state_path()
}

/// Git 全局配置事务状态。`original` 只在第一次接管某个键时记录，
/// `written` 是本应用最近一次写入的值；外部改动后不再覆盖。
#[derive(Debug, Serialize, Deserialize, Default)]
struct GitManagedState {
    version: u32,
    command: String,
    #[serde(default)]
    original: BTreeMap<String, ManagedValue>,
    #[serde(default)]
    written: BTreeMap<String, ManagedValue>,
}

async fn git_get(cmd: &str, key: &str) -> Result<ManagedValue> {
    let out = run_command(cmd, &["config", "--global", "--get-all", key]).await?;
    if out.success {
        let values: Vec<&str> = out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .collect();
        match values.len() {
            0 => Ok(ManagedValue::Absent),
            1 => Ok(ManagedValue::Present(values[0].to_string())),
            _ => anyhow::bail!(
                "Git 配置 {} 存在多个值，无法安全快照，请先手动合并后再启用",
                key
            ),
        }
    } else if out.code == 1 && out.stdout.trim().is_empty() && out.stderr.trim().is_empty() {
        // git config --get-all 在键不存在时固定返回 1；其他非零退出必须视为失败，
        // 否则命令损坏会被误判成“用户没有配置”，关闭时可能写错快照。
        Ok(ManagedValue::Absent)
    } else {
        anyhow::bail!(
            "读取 git 配置 {} 失败（退出码 {}）: {}",
            key,
            out.code,
            out.stderr.trim()
        )
    }
}

async fn git_write(cmd: &str, key: &str, desired: &ManagedValue) -> Result<()> {
    match desired {
        ManagedValue::Present(value) => {
            exec_checked(cmd, &["config", "--global", key, value]).await?;
        }
        ManagedValue::Absent => {
            if git_get(cmd, key).await? == ManagedValue::Absent {
                return Ok(());
            }
            exec_checked(cmd, &["config", "--global", "--unset", key]).await?;
        }
    }
    if &git_get(cmd, key).await? != desired {
        anyhow::bail!("git 配置 {} 写入后校验失败", key);
    }
    Ok(())
}

async fn apply_git_key(
    cmd: &str,
    key: &str,
    desired: &ManagedValue,
    state: &mut GitManagedState,
) -> Result<()> {
    let current = git_get(cmd, key).await?;
    let original = state
        .original
        .get(key)
        .cloned()
        .unwrap_or_else(|| current.clone());
    state.original.insert(key.to_string(), original.clone());
    if crate::util::managed::changed_externally(
        state.written.get(key),
        &current,
        &original,
        desired,
    ) {
        anyhow::bail!("Git 配置 {} 已被外部程序修改，拒绝覆盖", key);
    }
    if &current != desired {
        git_write(cmd, key, desired).await?;
    }
    state.written.insert(key.to_string(), desired.clone());
    save_state(&git_state_path(), state)?;
    Ok(())
}

async fn restore_git_state(state: &mut GitManagedState, only_if_written: bool) -> Result<()> {
    let mut errors = Vec::new();
    let keys: Vec<String> = state.original.keys().cloned().collect();
    for key in keys {
        let written = state.written.get(&key).cloned();
        let original = state
            .original
            .get(&key)
            .cloned()
            .unwrap_or(ManagedValue::Absent);
        let current = match git_get(&state.command, &key).await {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("{}: {}", key, e));
                continue;
            }
        };
        if current == original {
            state.written.remove(&key);
            continue;
        }
        let changed_externally = match (&written, &current) {
            (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
            (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
            (Some(_), _) => true,
            (None, _) => only_if_written,
        };
        if changed_externally {
            log_warn!("Git 配置 {} 已被外部修改，保留当前值", key);
            state.written.remove(&key);
            continue;
        }
        if let Err(e) = git_write(&state.command, &key, &original).await {
            errors.push(format!("{}: {}", key, e));
            continue;
        }
        state.written.remove(&key);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("恢复 Git 配置失败: {}", errors.join("; "))
    }
}

pub struct GitPlugin;

impl GitPlugin {
    pub fn command(config: &Value) -> String {
        config
            .pointer("/plugin/git/setting/command")
            .and_then(|v| v.as_str())
            .filter(|v| !v.trim().is_empty())
            .unwrap_or("git")
            .to_string()
    }

    pub async fn open_proxy(config: &Value, ip: &str, https_port: u16) -> Result<()> {
        let cmd = Self::command(config);
        let ssl_verify = as_bool(config.pointer("/plugin/git/setting/sslVerify"), true);
        let proxy = format!("http://{}:{}", ip, https_port);
        let path = git_state_path();
        let mut state: GitManagedState = load_state(&path)?.unwrap_or_default();
        if !state.command.is_empty() && state.command != cmd {
            anyhow::bail!(
                "Git 托管状态记录的 git 命令与当前配置不一致: {} != {}",
                state.command,
                cmd
            );
        }
        state.version = 1;
        state.command = cmd.clone();

        let mut desired: Vec<(String, ManagedValue)> = vec![
            ("http.proxy".into(), ManagedValue::Present(proxy.clone())),
            ("https.proxy".into(), ManagedValue::Present(proxy)),
            (
                "http.sslVerify".into(),
                ManagedValue::Present(ssl_verify.to_string()),
            ),
            // 历史版本误写的非法键
            ("http.proxyHttp".into(), ManagedValue::Absent),
        ];
        if let Some(Value::Object(list)) = config.pointer("/plugin/git/setting/noProxyUrls") {
            for (url, enabled) in list {
                if as_bool(Some(enabled), false) {
                    desired.push((format!("http.{}.proxy", url), ManagedValue::Absent));
                }
            }
        }

        let mut applied: Vec<String> = Vec::new();
        let mut result: Result<()> = Ok(());
        for (key, value) in &desired {
            if let Err(e) = apply_git_key(&cmd, key, value, &mut state).await {
                result = Err(e);
                break;
            }
            applied.push(key.clone());
        }
        if let Err(e) = result {
            let mut rollback_errors = Vec::new();
            for key in &applied {
                let original = state
                    .original
                    .get(key)
                    .cloned()
                    .unwrap_or(ManagedValue::Absent);
                let current = git_get(&cmd, key).await.unwrap_or(ManagedValue::Absent);
                let written = state.written.get(key).cloned();
                let changed_externally = match (&written, &current) {
                    (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
                    (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
                    (Some(_), _) => true,
                    (None, _) => true,
                };
                if changed_externally && current != original {
                    rollback_errors.push(format!("{}: 已被外部修改", key));
                    continue;
                }
                if let Err(re) = git_write(&cmd, key, &original).await {
                    rollback_errors.push(format!("{}: {}", key, re));
                } else {
                    state.written.remove(key);
                }
            }
            if rollback_errors.is_empty() {
                let _ = std::fs::remove_file(&path);
                anyhow::bail!("Git 代理开启失败，已回滚: {}", e);
            }
            save_state(&path, &state)?;
            anyhow::bail!(
                "Git 代理开启失败且回滚不完整: {}；残留: {}",
                e,
                rollback_errors.join("; ")
            );
        }

        save_state(&path, &state)?;
        log_info!("Git 代理已开启: {}:{}", ip, https_port);
        Ok(())
    }

    pub async fn close_proxy(config: &Value) -> Result<()> {
        let cmd = Self::command(config);
        let path = git_state_path();
        let Some(mut state): Option<GitManagedState> = load_state(&path)? else {
            return Self::legacy_cleanup(config, &cmd).await;
        };
        if state.command.is_empty() {
            state.command = cmd;
        }
        match restore_git_state(&mut state, true).await {
            Ok(()) => {}
            Err(e) => {
                save_state(&path, &state)?;
                anyhow::bail!("Git 代理关闭未完全恢复: {}", e);
            }
        }
        if state.written.is_empty() {
            let _ = std::fs::remove_file(path);
        } else {
            save_state(&path, &state)?;
        }
        log_info!("Git 代理已关闭，用户原配置已恢复");
        Ok(())
    }

    /// 无快照时只删除明确指向本应用端口的代理引用，不触碰 sslVerify、
    /// 绕过列表或用户自己设置的其他代理。
    async fn legacy_cleanup(config: &Value, cmd: &str) -> Result<()> {
        let port = config
            .pointer("/server/port")
            .and_then(|v| v.as_u64())
            .unwrap_or(31181) as u16;
        let mut errors = Vec::new();
        for key in ["http.proxy", "https.proxy"] {
            match git_get(cmd, key).await {
                Ok(ManagedValue::Present(value))
                    if crate::sysproxy::proxy_server_is_local(
                        &value,
                        &[port, port.saturating_sub(1)],
                    ) =>
                {
                    if let Err(e) = git_write(cmd, key, &ManagedValue::Absent).await {
                        errors.push(format!("{}: {}", key, e));
                    }
                }
                Ok(_) => {}
                Err(e) => errors.push(format!("{}: {}", key, e)),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("Git 兼容清理未完全完成: {}", errors.join("; "))
        }
    }
}

// ------------------------------------------------------------------ PIP

fn pip_state_path() -> std::path::PathBuf {
    crate::util::paths::pip_managed_state_path()
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PipManagedState {
    version: u32,
    command: String,
    #[serde(default)]
    original: BTreeMap<String, ManagedValue>,
    #[serde(default)]
    written: BTreeMap<String, ManagedValue>,
}

async fn pip_get(cmd: &str, key: &str) -> Result<ManagedValue> {
    let out = run_command(cmd, &["config", "get", key]).await?;
    if out.success {
        return Ok(ManagedValue::from_option(Some(
            out.stdout.trim().to_string(),
        )));
    }
    let stderr = out.stderr.to_lowercase();
    if out.code == 1 && (stderr.contains("no such key") || stderr.contains("no section")) {
        Ok(ManagedValue::Absent)
    } else {
        anyhow::bail!(
            "读取 pip 配置 {} 失败（退出码 {}）: {}",
            key,
            out.code,
            out.stderr.trim()
        )
    }
}

async fn pip_write(cmd: &str, key: &str, desired: &ManagedValue) -> Result<()> {
    match desired {
        ManagedValue::Present(value) => {
            exec_checked(cmd, &["config", "set", key, value]).await?;
        }
        ManagedValue::Absent => {
            if pip_get(cmd, key).await? == ManagedValue::Absent {
                return Ok(());
            }
            exec_checked(cmd, &["config", "unset", key]).await?;
        }
    }
    if &pip_get(cmd, key).await? != desired {
        anyhow::bail!("pip 配置 {} 写入后校验失败", key);
    }
    Ok(())
}

async fn apply_pip_key(
    cmd: &str,
    key: &str,
    desired: &ManagedValue,
    state: &mut PipManagedState,
) -> Result<()> {
    let current = pip_get(cmd, key).await?;
    let original = state
        .original
        .get(key)
        .cloned()
        .unwrap_or_else(|| current.clone());
    state.original.insert(key.to_string(), original.clone());
    if crate::util::managed::changed_externally(
        state.written.get(key),
        &current,
        &original,
        desired,
    ) {
        anyhow::bail!("PIP 配置 {} 已被外部程序修改，拒绝覆盖", key);
    }
    if &current != desired {
        pip_write(cmd, key, desired).await?;
    }
    state.written.insert(key.to_string(), desired.clone());
    save_state(&pip_state_path(), state)?;
    Ok(())
}

async fn restore_pip_state(state: &mut PipManagedState, only_if_written: bool) -> Result<()> {
    let mut errors = Vec::new();
    let keys: Vec<String> = state.original.keys().cloned().collect();
    for key in keys {
        let written = state.written.get(&key).cloned();
        let original = state
            .original
            .get(&key)
            .cloned()
            .unwrap_or(ManagedValue::Absent);
        let current = match pip_get(&state.command, &key).await {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("{}: {}", key, e));
                continue;
            }
        };
        if current == original {
            state.written.remove(&key);
            continue;
        }
        let changed_externally = match (&written, &current) {
            (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
            (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
            (Some(_), _) => true,
            (None, _) => only_if_written,
        };
        if changed_externally {
            log_warn!("PIP 配置 {} 已被外部修改，保留当前值", key);
            state.written.remove(&key);
            continue;
        }
        if let Err(e) = pip_write(&state.command, &key, &original).await {
            errors.push(format!("{}: {}", key, e));
            continue;
        }
        state.written.remove(&key);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("恢复 PIP 配置失败: {}", errors.join("; "))
    }
}

pub struct PipPlugin;

impl PipPlugin {
    pub fn command(config: &Value) -> String {
        config
            .pointer("/plugin/pip/setting/command")
            .and_then(|v| v.as_str())
            .unwrap_or("pip")
            .to_string()
    }

    pub fn registry(config: &Value) -> String {
        config
            .pointer("/plugin/pip/setting/registry")
            .and_then(|v| v.as_str())
            .unwrap_or("https://pypi.org/simple/")
            .to_string()
    }

    pub async fn open_proxy(config: &Value, ip: &str, port: u16) -> Result<()> {
        let cmd = Self::command(config);
        let registry = Self::registry(config);
        let trusted_host = config
            .pointer("/plugin/pip/setting/trustedHost")
            .and_then(|v| v.as_str())
            .unwrap_or("pypi.org")
            .to_string();
        let path = pip_state_path();
        let mut state: PipManagedState = load_state(&path)?.unwrap_or_default();
        if !state.command.is_empty() && state.command != cmd {
            anyhow::bail!(
                "PIP 托管状态记录的 pip 命令与当前配置不一致: {} != {}",
                state.command,
                cmd
            );
        }
        state.version = 1;
        state.command = cmd.clone();

        let desired = [
            ("global.index-url", registry.clone()),
            ("global.trusted-host", trusted_host),
            ("global.proxy", format!("http://{}:{}", ip, port)),
        ];
        let mut applied: Vec<String> = Vec::new();
        let mut result: Result<()> = Ok(());
        for (key, value) in &desired {
            if let Err(e) =
                apply_pip_key(&cmd, key, &ManagedValue::Present(value.clone()), &mut state).await
            {
                result = Err(e);
                break;
            }
            applied.push(key.to_string());
        }
        if let Err(e) = result {
            let mut rollback_errors = Vec::new();
            for key in &applied {
                let original = state
                    .original
                    .get(key)
                    .cloned()
                    .unwrap_or(ManagedValue::Absent);
                let current = pip_get(&cmd, key).await.unwrap_or(ManagedValue::Absent);
                let written = state.written.get(key).cloned();
                let changed_externally = match (&written, &current) {
                    (Some(ManagedValue::Present(w)), ManagedValue::Present(c)) => w != c,
                    (Some(ManagedValue::Absent), ManagedValue::Absent) => false,
                    (Some(_), _) => true,
                    (None, _) => true,
                };
                if changed_externally && current != original {
                    rollback_errors.push(format!("{}: 已被外部修改", key));
                    continue;
                }
                if let Err(re) = pip_write(&cmd, key, &original).await {
                    rollback_errors.push(format!("{}: {}", key, re));
                } else {
                    state.written.remove(key);
                }
            }
            if rollback_errors.is_empty() {
                let _ = std::fs::remove_file(&path);
                anyhow::bail!("PIP 加速开启失败，已回滚: {}", e);
            }
            save_state(&path, &state)?;
            anyhow::bail!(
                "PIP 加速开启失败且回滚不完整: {}；残留: {}",
                e,
                rollback_errors.join("; ")
            );
        }
        save_state(&path, &state)?;
        log_info!("PIP 加速已开启，index-url: {}", registry);
        Ok(())
    }

    pub async fn close_proxy(config: &Value) -> Result<()> {
        let cmd = Self::command(config);
        let path = pip_state_path();
        let Some(mut state): Option<PipManagedState> = load_state(&path)? else {
            return Self::legacy_cleanup(config, &cmd).await;
        };
        if state.command.is_empty() {
            state.command = cmd;
        }
        match restore_pip_state(&mut state, true).await {
            Ok(()) => {}
            Err(e) => {
                save_state(&path, &state)?;
                anyhow::bail!("PIP 加速关闭未完全恢复: {}", e);
            }
        }
        if state.written.is_empty() {
            let _ = std::fs::remove_file(path);
        } else {
            save_state(&path, &state)?;
        }
        log_info!("PIP 加速已关闭，用户原配置已恢复");
        Ok(())
    }

    /// 无快照时只删除与本次配置完全一致的值，避免清掉用户自设镜像。
    async fn legacy_cleanup(config: &Value, cmd: &str) -> Result<()> {
        let registry = Self::registry(config);
        let trusted_host = config
            .pointer("/plugin/pip/setting/trustedHost")
            .and_then(|v| v.as_str())
            .unwrap_or("pypi.org")
            .to_string();
        let port = config
            .pointer("/server/port")
            .and_then(|v| v.as_u64())
            .unwrap_or(31181) as u16;
        let mut errors = Vec::new();
        for (key, owned) in [
            ("global.index-url", registry),
            ("global.trusted-host", trusted_host),
        ] {
            match pip_get(cmd, key).await {
                Ok(ManagedValue::Present(value)) if value == owned => {
                    if let Err(e) = pip_write(cmd, key, &ManagedValue::Absent).await {
                        errors.push(format!("{}: {}", key, e));
                    }
                }
                Ok(_) => {}
                Err(e) => errors.push(format!("{}: {}", key, e)),
            }
        }
        match pip_get(cmd, "global.proxy").await {
            Ok(ManagedValue::Present(value))
                if crate::sysproxy::proxy_server_is_local(
                    &value,
                    &[port, port.saturating_sub(1)],
                ) =>
            {
                if let Err(e) = pip_write(cmd, "global.proxy", &ManagedValue::Absent).await {
                    errors.push(format!("global.proxy: {}", e));
                }
            }
            Ok(_) => {}
            Err(e) => errors.push(format!("global.proxy: {}", e)),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("PIP 兼容清理未完全完成: {}", errors.join("; "))
        }
    }
}

// ------------------------------------------------------------------ 环境变量

#[cfg(target_os = "windows")]
fn user_env_key() -> Result<winreg::RegKey> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
        .map_err(|e| anyhow::anyhow!(r"打开 HKCU\Environment 失败: {}", e))
}

/// 读取当前用户环境变量（Windows）
#[cfg(target_os = "windows")]
fn user_env_value(key: &str) -> Option<String> {
    user_env_key().ok()?.get_value::<String, _>(key).ok()
}

#[cfg(not(target_os = "windows"))]
fn user_env_value(_key: &str) -> Option<String> {
    None
}

/// 写入 HKCU 用户环境变量，读回校验并广播 WM_SETTINGCHANGE。
/// 不使用 setx：避免 1024 字符截断，并且 setx 的失败无法可靠映射到本进程。
async fn write_user_env_checked(key: &str, value: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let environment = user_env_key()?;
        environment
            .set_value(key, &value.to_string())
            .map_err(|e| anyhow::anyhow!("写入环境变量 {} 失败: {}", key, e))?;
        let readback: String = environment
            .get_value(key)
            .map_err(|e| anyhow::anyhow!("读回环境变量 {} 失败: {}", key, e))?;
        if readback != value {
            anyhow::bail!("环境变量 {} 写入后校验失败", key);
        }
        crate::sysproxy::notify_env_changed();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (key, value);
        log_warn!("当前平台尚未实现用户环境变量写入: {}", key);
    }
    Ok(())
}

async fn delete_user_env_checked(key: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let environment = user_env_key()?;
        match environment.delete_value(key) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => anyhow::bail!("删除环境变量 {} 失败: {}", key, e),
        }
        if environment.get_value::<String, _>(key).is_ok() {
            anyhow::bail!("环境变量 {} 删除后仍存在", key);
        }
        crate::sysproxy::notify_env_changed();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = key;
    }
    Ok(())
}

pub async fn set_user_env(key: &str, value: &str) -> Result<()> {
    write_user_env_checked(key, value).await
}

/// 仅当环境变量值指向本应用 CA 证书时才删除，避免误删用户自行配置的值
pub async fn remove_user_env_if_path(key: &str, expected: &str) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    if user_env_value(key).is_some_and(|v| crate::sysproxy::is_same_path(&v, expected)) {
        delete_user_env_checked(key).await?;
    }
    Ok(())
}

pub async fn remove_user_env(key: &str) -> Result<()> {
    delete_user_env_checked(key).await
}

pub fn env_variables(config: &Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(Value::Object(envs)) = config.pointer("/plugin/node/envVariables") {
        for (k, v) in envs {
            if let Some(value) = v.as_str() {
                map.insert(k.clone(), value.to_string());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    /// npm 写 Windows 路径时不加引号也不转义：必须原样读回，
    /// 否则 `\tools` / `\npm` 会被当成 `\t` / `\n` 转义，写入后校验失败。
    #[test]
    fn npmrc_unquoted_windows_path_is_not_unescaped() {
        assert_eq!(
            parse_npmrc_value(Some(r"C:\tools\npm.pem")),
            Some(r"C:\tools\npm.pem".to_string())
        );
        assert_eq!(
            parse_npmrc_value(Some(r"C:\Users\newton\.dev-sidecar\ca-bundle.crt")),
            Some(r"C:\Users\newton\.dev-sidecar\ca-bundle.crt".to_string())
        );
    }

    /// 手写的双引号值需要反转义，且必须单遍处理反斜杠：
    /// `\\tools` 表示“反斜杠 + tools”，不能被当成制表符。
    #[test]
    fn npmrc_quoted_value_unescapes_single_pass() {
        assert_eq!(
            parse_npmrc_value(Some(r#""C:\\tools\\npm.pem""#)),
            Some(r"C:\tools\npm.pem".to_string())
        );
        // `\\` 必须整体消费，不能被当成 `\t` / `\n`
        assert_eq!(
            parse_npmrc_value(Some(r#""a\tb\nc\\d\"e""#)),
            Some("a\tb\nc\\d\"e".to_string())
        );
        // 未识别的转义原样保留
        assert_eq!(
            parse_npmrc_value(Some(r#""C:\data\ca.pem""#)),
            Some(r"C:\data\ca.pem".to_string())
        );
    }
}
