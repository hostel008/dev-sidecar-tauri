//! 外部配置的事务快照与原子持久化。
//!
//! 插件和系统代理会修改用户级配置。快照必须在第一次写入前生成，并在后续
//! 重复应用时保留最初值；状态文件使用临时文件 + rename 原子替换。

use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

/// 一个外部配置键在应用接管前的状态。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum ManagedValue {
    Absent,
    Present(String),
}

impl ManagedValue {
    pub fn from_option(value: Option<String>) -> Self {
        match value {
            Some(v) => Self::Present(v),
            None => Self::Absent,
        }
    }

    pub fn as_option(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::Present(v) => Some(v),
        }
    }
}

/// 读取状态文件；不存在时返回 None，损坏时返回错误而不是静默丢弃恢复能力。
pub fn load_state<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
            anyhow::anyhow!("读取状态文件失败 {}: {}", path.display(), e)
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(
            "读取状态文件失败 {}: {}",
            path.display(),
            e
        )),
    }
}

/// 原子写入状态文件。
pub fn save_state<T: Serialize>(path: &Path, state: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes)?;
    if let Err(first) = std::fs::rename(&tmp, path) {
        // Windows 上目标存在时个别文件系统会拒绝 rename，退化为覆盖写。
        if let Err(second) = std::fs::write(path, &bytes) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow::anyhow!(
                "写入状态文件失败 {}: rename={} overwrite={}",
                path.display(),
                first,
                second
            ));
        }
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(())
}

/// 从 JSON 对象移除敏感值，用于诊断输出。
pub fn redact_json(mut value: Value, keys: &[&str]) -> Value {
    fn walk(value: &mut Value, keys: &[&str]) {
        match value {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if keys.iter().any(|needle| {
                        k.eq_ignore_ascii_case(needle)
                            || k.to_ascii_lowercase()
                                .contains(&needle.to_ascii_lowercase())
                    }) {
                        *v = Value::String("<redacted>".to_string());
                    } else {
                        walk(v, keys);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, keys);
                }
            }
            _ => {}
        }
    }
    walk(&mut value, keys);
    value
}

/// 判断某个键的当前值是否已经被外部程序改过。
///
/// 只有“当前值既不等于我们上次写入的值、也不等于接管前原值、也不等于本次
/// 期望值”才算外部修改。该判断同时适用于写入 `Present` 和删除（`Absent`），
/// 避免旧值 Absent 时用户重新设置的值被静默删除。
pub fn changed_externally(
    written: Option<&ManagedValue>,
    current: &ManagedValue,
    original: &ManagedValue,
    desired: &ManagedValue,
) -> bool {
    written.is_some_and(|written| current != written && current != original && current != desired)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &str) -> ManagedValue {
        ManagedValue::Present(v.to_string())
    }

    #[test]
    fn external_change_detection_covers_absent_targets() {
        // 本应用上次删除了该键，用户随后重新设置：不能再次删除。
        assert!(changed_externally(
            Some(&ManagedValue::Absent),
            &p("user"),
            &ManagedValue::Absent,
            &ManagedValue::Absent,
        ));
        // 本应用写入代理，用户改成自己的代理。
        assert!(changed_externally(
            Some(&p("http://127.0.0.1:31181")),
            &p("http://user:8080"),
            &p("http://old:8080"),
            &p("http://127.0.0.1:31181"),
        ));
        // 用户把值改回接管前原值，不视为外部修改。
        assert!(!changed_externally(
            Some(&p("http://127.0.0.1:31181")),
            &p("http://old:8080"),
            &p("http://old:8080"),
            &p("http://127.0.0.1:31181"),
        ));
        // 当前已经是本次期望值（重复开启）无需报错。
        assert!(!changed_externally(
            Some(&p("http://old:8080")),
            &p("http://127.0.0.1:31181"),
            &p("http://old:8080"),
            &p("http://127.0.0.1:31181"),
        ));
        // 没有托管记录时不做外部修改判断。
        assert!(!changed_externally(
            None,
            &p("user"),
            &p("user"),
            &p("http://127.0.0.1:31181"),
        ));
    }
}
