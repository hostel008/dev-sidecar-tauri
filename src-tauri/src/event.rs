//! 向前端推送事件（status / speed / traffic / error / config）

use parking_lot::RwLock;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use tauri::{Emitter, Manager};

static APP_HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();

pub fn init(app: &tauri::AppHandle) {
    let _ = APP_HANDLE.set(app.clone());
}

fn emit(name: &str, payload: serde_json::Value) {
    if let Some(app) = APP_HANDLE.get() {
        let _ = app.emit(name, payload);
    }
}

// ---------------------------------------------------------------- 流量统计

pub struct Traffic {
    pub upload: AtomicU64,
    pub download: AtomicU64,
    last_upload: RwLock<u64>,
    last_download: RwLock<u64>,
    upload_speed: AtomicU64,
    download_speed: AtomicU64,
    pub start_time: RwLock<u64>,
}

impl Traffic {
    fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Traffic {
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            last_upload: RwLock::new(0),
            last_download: RwLock::new(0),
            upload_speed: AtomicU64::new(0),
            download_speed: AtomicU64::new(0),
            start_time: RwLock::new(now),
        }
    }
    pub fn add_upload(&self, n: u64) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_download(&self, n: u64) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }
    pub fn reset(&self) {
        self.upload.store(0, Ordering::Relaxed);
        self.download.store(0, Ordering::Relaxed);
        self.upload_speed.store(0, Ordering::Relaxed);
        self.download_speed.store(0, Ordering::Relaxed);
        *self.start_time.write() = now_ms();
    }
    /// 每秒计算一次速率并推送
    pub async fn monitor(&self) {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            let up = self.upload.load(Ordering::Relaxed);
            let down = self.download.load(Ordering::Relaxed);
            let (lu, ld) = {
                let last_up = *self.last_upload.read();
                let last_down = *self.last_download.read();
                (last_up, last_down)
            };
            let up_speed = up.saturating_sub(lu);
            let down_speed = down.saturating_sub(ld);
            self.upload_speed.store(up_speed, Ordering::Relaxed);
            self.download_speed.store(down_speed, Ordering::Relaxed);
            *self.last_upload.write() = up;
            *self.last_download.write() = down;
            emit_traffic(up, down, up_speed, down_speed);
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

static TRAFFIC: OnceLock<Traffic> = OnceLock::new();

pub fn traffic() -> &'static Traffic {
    TRAFFIC.get_or_init(Traffic::new)
}

pub fn emit_traffic(upload: u64, download: u64, upload_speed: u64, download_speed: u64) {
    emit(
        "traffic",
        json!({
            "upload": upload,
            "download": download,
            "uploadSpeed": upload_speed,
            "downloadSpeed": download_speed,
        }),
    );
}

// ---------------------------------------------------------------- 各类事件

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKey {
    Server,
    Proxy,
    Node,
    Git,
    Pip,
    RemoteConfig,
    Upgrade,
}

impl StatusKey {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusKey::Server => "server",
            StatusKey::Proxy => "proxy",
            StatusKey::Node => "node",
            StatusKey::Git => "git",
            StatusKey::Pip => "pip",
            StatusKey::RemoteConfig => "remoteConfig",
            StatusKey::Upgrade => "upgrade",
        }
    }
}

pub fn emit_status(key: StatusKey, status: &str) {
    emit(
        "status",
        json!({
            "key": key.as_str(),
            "status": status,
        }),
    );
}

pub fn emit_speed(results: &[crate::speed::SpeedTestResult]) {
    let list: Vec<serde_json::Value> = results.iter().map(|r| r.to_json()).collect();
    emit("speed", json!({ "resultList": list }));
}

pub fn emit_sni_list(list: serde_json::Value) {
    emit("sniList", list);
}

pub fn emit_speed_testing(testing: bool) {
    emit("speedTesting", json!({ "testing": testing }));
}

pub fn emit_error(title: &str, msg: &str) {
    emit(
        "error",
        json!({
            "title": title,
            "msg": msg,
        }),
    );
}

pub fn emit_log(level: &str, msg: &str) {
    emit("log", json!({ "level": level, "msg": msg }));
}

pub fn emit_config_changed(config: serde_json::Value) {
    emit("config", config);
}

/// 兼容旧版：取出主窗口用于前端交互
pub fn _window() -> Option<tauri::WebviewWindow> {
    APP_HANDLE
        .get()
        .and_then(|app| app.get_webview_window("main"))
}
