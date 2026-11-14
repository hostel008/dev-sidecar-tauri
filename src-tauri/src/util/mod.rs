pub mod diag;
pub mod jsonc;
pub mod log;
pub mod managed;
pub mod paths;

use serde_json::Value;

/// 创建不弹出控制台窗口的子进程命令
/// （Windows GUI 程序默认会为子进程弹出新控制台，需加 CREATE_NO_WINDOW）
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
pub fn hidden_command(cmd: &str) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut command = std::process::Command::new(cmd);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

#[cfg(not(target_os = "windows"))]
pub fn hidden_command(cmd: &str) -> std::process::Command {
    std::process::Command::new(cmd)
}

/// 同上，供 async 场景使用（直接在 tokio Command 上设置标志，不做类型转换）
pub fn hidden_tokio_command(cmd: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(cmd);
    #[cfg(target_os = "windows")]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// lodash merge 风格：对象深合并，数组整体替换
pub fn merge(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                match a.get_mut(k) {
                    Some(orig) => merge(orig, v),
                    None => {
                        a.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (a, Value::Null) => {
            // null 视为标记，交由 delete_null_items 处理
            let _ = a;
        }
        (a, b) => {
            if !b.is_null() {
                *a = b.clone();
            }
        }
    }
}

/// 删除值为 null 的项（原版 merge.js 的 deleteNullItems）
pub fn delete_null_items(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                match map.get_mut(&k) {
                    Some(Value::Null) => {
                        map.remove(&k);
                    }
                    Some(v) => delete_null_items(v),
                    None => {}
                }
            }
        }
        Value::Array(arr) => {
            arr.retain(|v| !v.is_null());
            for v in arr.iter_mut() {
                delete_null_items(v);
            }
        }
        _ => {}
    }
}

/// 计算 new 相对 default 的差异（用于保存用户配置）
pub fn diff(default: &Value, value: &Value) -> Value {
    match (default, value) {
        (Value::Object(d), Value::Object(v)) => {
            let mut out = serde_json::Map::new();
            for (k, new_v) in v {
                match d.get(k) {
                    Some(d_v) => {
                        let sub = diff(d_v, new_v);
                        match sub {
                            Value::Object(m) if !m.is_empty() => {
                                out.insert(k.clone(), Value::Object(m));
                            }
                            Value::Object(_) => {
                                // 空对象表示无差异，不写入 diff
                            }
                            Value::Array(a) if !a.is_empty() => {
                                out.insert(k.clone(), Value::Array(a));
                            }
                            Value::Null => {}
                            scalar => {
                                out.insert(k.clone(), scalar);
                            }
                        }
                    }
                    None => {
                        out.insert(k.clone(), new_v.clone());
                    }
                }
            }
            Value::Object(out)
        }
        (Value::Array(d), Value::Array(v)) => {
            if d == v {
                Value::Null
            } else {
                Value::Array(v.clone())
            }
        }
        (d, v) => {
            if d == v {
                Value::Null
            } else {
                v.clone()
            }
        }
    }
}

/// 点分路径取值
pub fn get_by_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// 点分路径设值
pub fn set_by_path(root: &mut Value, path: &str, value: Value) {
    let segs: Vec<&str> = path.split('.').collect();
    if segs.is_empty() {
        return;
    }
    let mut cur = root;
    for i in 0..segs.len() - 1 {
        if !cur.get(segs[i]).map(|v| v.is_object()).unwrap_or(false) {
            cur[segs[i]] = Value::Object(serde_json::Map::new());
        }
        cur = cur.get_mut(segs[i]).unwrap();
    }
    cur[segs[segs.len() - 1]] = value;
}

/// 简易 humanize 字节数
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut idx = 0;
    while size >= 1024.0 && idx < UNITS.len() - 1 {
        size /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNITS[idx])
    } else {
        format!("{:.2} {}", size, UNITS[idx])
    }
}

#[cfg(test)]
mod tests {
    /// 校验隐藏窗口命令可正常创建并执行（Windows 下带 CREATE_NO_WINDOW 标志）
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn hidden_tokio_command_runs() {
        let mut command = super::hidden_tokio_command("cmd");
        command.args(["/C", "exit", "0"]);
        let output = command.output().await.expect("启动隐藏窗口命令失败");
        assert!(output.status.success(), "隐藏窗口命令应执行成功");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn hidden_command_runs() {
        let output = super::hidden_command("cmd")
            .args(["/C", "exit", "0"])
            .output()
            .expect("启动隐藏窗口命令失败");
        assert!(output.status.success(), "隐藏窗口命令应执行成功");
    }
}
