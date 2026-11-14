//! 全局路径、用户目录相关工具

use std::path::PathBuf;

/// 获取用户基础目录 `~/.dev-sidecar`
pub fn user_base_path() -> PathBuf {
    if let Ok(dir) = std::env::var("DEV_SIDECAR_HOME") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".dev-sidecar")
}

/// 用户自定义配置文件 `~/.dev-sidecar/config.json`
pub fn user_config_path() -> PathBuf {
    user_base_path().join("config.json")
}

/// 共享远程配置文件
pub fn remote_config_path() -> PathBuf {
    user_base_path().join("remote_config.json")
}

/// 个人远程配置文件
pub fn personal_remote_config_path() -> PathBuf {
    user_base_path().join("remote_config_personal.json")
}

/// 运行时配置（原版 running.json）
pub fn running_config_path() -> PathBuf {
    user_base_path().join("running.json")
}

/// CA 根证书
pub fn ca_cert_path() -> PathBuf {
    user_base_path().join("dev-sidecar.ca.crt")
}

/// CA 私钥
pub fn ca_key_path() -> PathBuf {
    user_base_path().join("dev-sidecar.ca.key.pem")
}

/// 合并 CA bundle（系统根证书 + DevSidecar CA）。
/// 用于 `cafile` / `SSL_CERT_FILE` 这类「替换默认信任库」语义的配置项：
/// 若只指向 DevSidecar CA，未走 MITM 的站点会因缺少公共根证书而报
/// `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`
pub fn ca_bundle_path() -> PathBuf {
    user_base_path().join("dev-sidecar.ca-bundle.crt")
}

/// 日志目录
pub fn log_dir() -> PathBuf {
    user_base_path().join("logs")
}

/// 系统代理环境变量备份文件
pub fn proxy_env_backup_path() -> PathBuf {
    user_base_path().join("proxy-env-backup.json")
}

/// NPM 插件托管配置快照（原始值 + 本次写入期望值）
pub fn npm_managed_state_path() -> PathBuf {
    user_base_path().join("npm-managed-state.json")
}

/// Git 插件托管配置快照（写入前原值 + 本次写入值）
pub fn git_managed_state_path() -> PathBuf {
    user_base_path().join("git-managed-state.json")
}

/// PIP 插件托管配置快照
pub fn pip_managed_state_path() -> PathBuf {
    user_base_path().join("pip-managed-state.json")
}

/// Windows 系统代理的事务快照
pub fn sysproxy_managed_state_path() -> PathBuf {
    user_base_path().join("sysproxy-managed-state.json")
}

/// 运行编排 journal（期望状态、进程代次与最近错误）
pub fn runtime_state_path() -> PathBuf {
    user_base_path().join("runtime-state.json")
}

pub fn ensure_user_dir() -> anyhow::Result<()> {
    let base = user_base_path();
    std::fs::create_dir_all(&base)?;
    std::fs::create_dir_all(log_dir())?;
    Ok(())
}
