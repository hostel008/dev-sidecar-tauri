//! 简易日志：按天分文件 + 按大小滚动，写入 `~/.dev-sidecar/logs/*.log`

use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::OnceLock;

pub const LEVEL_DEBUG: u8 = 0;
pub const LEVEL_INFO: u8 = 1;
pub const LEVEL_WARN: u8 = 2;
pub const LEVEL_ERROR: u8 = 3;

struct Writer {
    file: Option<File>,
    path: std::path::PathBuf,
    size: u64,
}

struct Logger {
    disabled: Mutex<bool>,
    dir: Mutex<std::path::PathBuf>,
    max_size: Mutex<u64>,
    writer: Mutex<Writer>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn logger() -> &'static Logger {
    LOGGER.get_or_init(|| Logger {
        disabled: Mutex::new(false),
        dir: Mutex::new(super::paths::log_dir()),
        max_size: Mutex::new(50 * 1024 * 1024),
        writer: Mutex::new(Writer {
            file: None,
            path: std::path::PathBuf::new(),
            size: 0,
        }),
    })
}

pub fn set_disabled(v: bool) {
    *logger().disabled.lock() = v;
}

pub fn is_disabled() -> bool {
    *logger().disabled.lock()
}

pub fn set_dir(dir: std::path::PathBuf) {
    *logger().dir.lock() = dir;
    let mut w = logger().writer.lock();
    w.file = None;
    w.size = 0;
}

pub fn set_max_file_size(size: u64) {
    *logger().max_size.lock() = size;
}

fn level_name(level: u8) -> &'static str {
    match level {
        LEVEL_DEBUG => "DEBUG",
        LEVEL_INFO => "INFO",
        LEVEL_WARN => "WARN",
        _ => "ERROR",
    }
}

/// 打开（或滚动）日志文件
fn ensure_writer(w: &mut Writer, dir: &std::path::PathBuf, max: u64) {
    let name = chrono::Local::now().format("%Y-%m-%d").to_string();
    let path = dir.join(format!("{}.log", name));

    // 目标文件变化，或文件句柄为空（set_dir 重置过、或上次打开失败）时（重）打开。
    // 注意：set_dir 不会重置 w.path，若这里只比路径，配置加载后文件名不变
    // 就会走进“路径未变”分支而 file 为空 —— 日志静默断写。
    if w.path != path || w.file.is_none() {
        if let Ok(f) = OpenOptions::new().create(true).append(true).open(&path) {
            w.size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            w.file = Some(f);
            w.path = path;
        } else {
            w.file = None;
        }
        return;
    }

    if w.size > max {
        let rotated = dir.join(format!(
            "{}.{}.log",
            name,
            chrono::Local::now().timestamp_millis()
        ));
        let _ = std::fs::rename(&path, rotated);
        if let Ok(f) = OpenOptions::new().create(true).append(true).open(&path) {
            w.file = Some(f);
            w.size = 0;
        }
    }
}

pub fn raw(level: u8, target: &str, msg: String) {
    if is_disabled() {
        return;
    }
    let now = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string();
    let line = format!("{} [{}] [{}] {}\n", now, level_name(level), target, msg);
    print!("{}", line);

    let lg = logger();
    let dir = lg.dir.lock().clone();
    let max = *lg.max_size.lock();
    let _ = std::fs::create_dir_all(&dir);
    let mut w = lg.writer.lock();
    ensure_writer(&mut w, &dir, max);
    if let Some(f) = w.file.as_mut() {
        let ok = f.write_all(line.as_bytes()).is_ok();
        let flushed = f.flush().is_ok();
        if ok && flushed {
            w.size += line.len() as u64;
        }
    }
}

#[allow(unused_macros)]
macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_DEBUG, module_path!(), format!($($arg)*)) };
}
#[allow(unused_macros)]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_INFO, module_path!(), format!($($arg)*)) };
}
#[allow(unused_macros)]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_WARN, module_path!(), format!($($arg)*)) };
}
#[allow(unused_macros)]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::util::log::raw($crate::util::log::LEVEL_ERROR, module_path!(), format!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归：配置加载会以默认目录调用 set_dir，此后必须继续写文件。
    /// 曾经 set_dir 只置空 file、不重置 path，导致之后的日志只进控制台、文件静默断写。
    #[test]
    fn logging_continues_after_set_dir() -> Result<(), Box<dyn std::error::Error>> {
        // 写入 crate 内的 target/（%TEMP% 在受限环境下可能不可写）
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;

        set_disabled(false);
        set_dir(dir.clone());
        raw(LEVEL_INFO, "test", "before-set-dir".to_string());
        // 模拟启动流程：加载配置时再次设置同一目录
        set_dir(dir.clone());
        raw(LEVEL_INFO, "test", "after-set-dir".to_string());

        let name = chrono::Local::now().format("%Y-%m-%d").to_string();
        let content = std::fs::read_to_string(dir.join(format!("{}.log", name)))?;
        assert!(
            content.contains("before-set-dir"),
            "首次写入丢失: {}",
            content
        );
        assert!(
            content.contains("after-set-dir"),
            "set_dir 之后写入丢失: {}",
            content
        );

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
