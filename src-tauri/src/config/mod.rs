//! 配置加载 / 合并 / 保存（对应原版 core/src/config-api.js 与 local-config-loader.js）

use anyhow::Result;
use parking_lot::RwLock;
use serde_json::Value;

const DEFAULT_JSON: &str = include_str!("default.json");

/// 读取默认配置（内置），并替换其中的路径占位符
pub fn build_default_config() -> Value {
    let user_base = crate::util::paths::user_base_path();
    let ca_cert = crate::util::paths::ca_cert_path();
    let ca_key = crate::util::paths::ca_key_path();
    let log_dir = crate::util::paths::log_dir();

    let rendered = DEFAULT_JSON
        .replace(
            "${userBase}",
            &user_base.to_string_lossy().replace('\\', "/"),
        )
        .replace("${caCert}", &ca_cert.to_string_lossy().replace('\\', "/"))
        .replace("${caKey}", &ca_key.to_string_lossy().replace('\\', "/"))
        .replace("${logDir}", &log_dir.to_string_lossy().replace('\\', "/"));

    match crate::util::jsonc::parse(&rendered) {
        Ok(v) => v,
        Err(e) => {
            log_error!("内置默认配置解析失败: {}", e);
            serde_json::json!({})
        }
    }
}

fn load_from_file(path: &std::path::Path) -> Value {
    if !path.exists() {
        return serde_json::json!({});
    }
    match std::fs::read_to_string(path) {
        Ok(content) => match crate::util::jsonc::parse(&content) {
            Ok(v) => v,
            Err(e) => {
                log_error!("解析配置文件失败: {}, error: {}", path.display(), e);
                serde_json::json!({})
            }
        },
        Err(e) => {
            log_error!("读取配置文件失败: {}, error: {}", path.display(), e);
            serde_json::json!({})
        }
    }
}

/// 原版 getConfigFromFiles：远程配置在前合并两次，保证优先级
pub fn get_config_from_files(user_config: &Value, default_config: &Value) -> Value {
    let mut merged = user_config.clone();
    let personal = load_from_file(&crate::util::paths::personal_remote_config_path());
    let shared = load_from_file(&crate::util::paths::remote_config_path());

    crate::util::merge(&mut merged, &personal);
    crate::util::merge(&mut merged, &shared);
    crate::util::merge(&mut merged, default_config);
    crate::util::merge(&mut merged, &shared);
    crate::util::merge(&mut merged, &personal);
    crate::util::merge(&mut merged, user_config);

    crate::util::delete_null_items(&mut merged);
    merged
}

pub struct ConfigStore {
    default: Value,
    current: RwLock<Value>,
}

impl ConfigStore {
    pub fn new() -> Result<Self> {
        crate::util::paths::ensure_user_dir()?;
        let default = build_default_config();
        let user_config = load_from_file(&crate::util::paths::user_config_path());
        let merged = get_config_from_files(&user_config, &default);
        Self::apply_log_settings(&merged);
        Ok(ConfigStore {
            default,
            current: RwLock::new(merged),
        })
    }

    pub fn get(&self) -> Value {
        self.current.read().clone()
    }

    pub fn default_config(&self) -> Value {
        self.default.clone()
    }

    pub fn reload(&self) -> Value {
        let user_config = load_from_file(&crate::util::paths::user_config_path());
        let merged = get_config_from_files(&user_config, &self.default);
        Self::apply_log_settings(&merged);
        *self.current.write() = merged.clone();
        merged
    }

    /// 保存用户配置（仅保存差异部分）
    pub fn save(&self, new_config: Value) -> Result<(Value, Value)> {
        let mut base = self.default.clone();
        crate::util::merge(
            &mut base,
            &load_from_file(&crate::util::paths::remote_config_path()),
        );
        crate::util::merge(
            &mut base,
            &load_from_file(&crate::util::paths::personal_remote_config_path()),
        );

        let diff = crate::util::diff(&base, &new_config);
        std::fs::write(
            crate::util::paths::user_config_path(),
            crate::util::jsonc::stringify(&diff),
        )?;
        log_info!("保存 config.json 自定义配置文件成功");
        let all = self.set(diff.clone());
        Ok((diff, all))
    }

    pub fn set(&self, user_config: Value) -> Value {
        let merged = get_config_from_files(&user_config, &self.default);
        Self::apply_log_settings(&merged);
        *self.current.write() = merged.clone();
        merged
    }

    pub fn update(&self, part: Value) -> Result<Value> {
        let mut new = self.get();
        crate::util::merge(&mut new, &part);
        Ok(self.save(new)?.1)
    }

    pub fn reset_default(&self, key: Option<&str>) -> Result<Value> {
        match key {
            Some(k) => {
                let value = crate::util::get_by_path(&self.default, k).cloned();
                let mut current = self.get();
                if let Some(v) = value {
                    crate::util::set_by_path(&mut current, k, v);
                }
                Ok(self.save(current)?.1)
            }
            None => {
                // 备份并清空用户配置文件，否则下次启动旧配置会重新生效
                let path = crate::util::paths::user_config_path();
                if path.exists() {
                    if let Ok(original) = std::fs::read_to_string(&path) {
                        if !original.trim().is_empty() {
                            let bak = format!(
                                "{}.{}.bak.json",
                                path.to_string_lossy(),
                                chrono::Local::now().timestamp_millis()
                            );
                            let _ = std::fs::write(&bak, &original);
                        }
                    }
                    let _ = std::fs::write(&path, "{}");
                }
                let merged = get_config_from_files(&serde_json::json!({}), &self.default);
                Self::apply_log_settings(&merged);
                *self.current.write() = merged.clone();
                Ok(merged)
            }
        }
    }

    /// 恢复出厂设置：备份并清空用户配置
    pub fn remove_user_config(&self) -> Result<bool> {
        let path = crate::util::paths::user_config_path();
        if !path.exists() {
            return Ok(false);
        }
        let original = std::fs::read_to_string(&path)?;
        if original.replace(char::is_whitespace, "").len() < 5 {
            std::fs::write(&path, "{}")?;
            self.reload();
            return Ok(false);
        }
        let bak = format!(
            "{}.{}.bak.json",
            path.to_string_lossy(),
            chrono::Local::now().timestamp_millis()
        );
        std::fs::write(&bak, &original)?;
        std::fs::write(&path, "{}")?;
        self.reload();
        log_info!("备份用户配置文件成功: {}", bak);
        Ok(true)
    }

    fn apply_log_settings(config: &Value) {
        let app = config.get("app");
        let disabled = app
            .and_then(|a| a.get("logDisabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        crate::util::log::set_disabled(disabled);

        if let Some(dir) = app
            .and_then(|a| a.get("logFileSavePath"))
            .and_then(|v| v.as_str())
        {
            if !dir.is_empty() {
                crate::util::log::set_dir(std::path::PathBuf::from(dir));
            }
        }
        let size = app
            .and_then(|a| a.get("maxLogFileSize"))
            .and_then(|v| v.as_f64());
        let unit = app
            .and_then(|a| a.get("maxLogFileSizeUnit"))
            .and_then(|v| v.as_str())
            .unwrap_or("GB");
        if let Some(size) = size {
            let bytes = if unit.eq_ignore_ascii_case("MB") {
                (size * 1024.0 * 1024.0) as u64
            } else {
                (size * 1024.0 * 1024.0 * 1024.0) as u64
            };
            crate::util::log::set_max_file_size(bytes);
        }
    }

    /// 下载远程配置并落盘
    pub async fn download_remote_config(&self) -> Result<()> {
        let (enabled, url, personal_url) = {
            let cfg = self.get();
            let remote = cfg
                .pointer("/app/remoteConfig")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            (
                remote
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                remote
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                remote
                    .get("personalUrl")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        };

        if !enabled {
            let _ = std::fs::remove_file(crate::util::paths::remote_config_path());
            let _ = std::fs::remove_file(crate::util::paths::personal_remote_config_path());
            return Ok(());
        }

        Self::do_download(&url, &crate::util::paths::remote_config_path()).await?;
        Self::do_download(
            &personal_url,
            &crate::util::paths::personal_remote_config_path(),
        )
        .await?;
        Ok(())
    }

    async fn do_download(url: &str, save_path: &std::path::Path) -> Result<()> {
        if url.is_empty() {
            let _ = std::fs::remove_file(save_path);
            return Ok(());
        }
        log_info!("开始下载远程配置: {}", url);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let resp = client
            .get(url)
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .send()
            .await?;
        let body = resp.text().await?;
        if body.trim().len() < 2 {
            log_warn!("下载远程配置成功，但内容为空: {}", url);
            return Ok(());
        }
        // 校验内容可被解析
        crate::util::jsonc::parse(&body)?;
        std::fs::write(save_path, body)?;
        log_info!("保存远程配置文件成功: {}", save_path.display());
        Ok(())
    }
}
