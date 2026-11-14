#[macro_use]
mod macros;

pub mod util;

pub mod app;
pub mod commands;
pub mod config;
pub mod dns;
pub mod event;
pub mod matcher;
pub mod plugin;
pub mod proxy;
pub mod speed;
pub mod sysproxy;
pub mod tls;

use tauri::{Emitter, Manager, WebviewWindowBuilder};

fn build_tray(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{MenuBuilder, MenuItemBuilder};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItemBuilder::with_id("show", "显示窗口").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "退出").build(app)?;
    let menu = MenuBuilder::new(app).items(&[&show, &quit]).build()?;

    let _ = TrayIconBuilder::with_id("main-tray")
        .tooltip("DevSidecar")
        .icon(app.default_window_icon().cloned().ok_or("缺少图标")?)
        .menu(&menu)
        // 左键不弹菜单，交给 on_tray_icon_event 处理
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
        })
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                // 退出前恢复系统代理、回滚插件配置，避免残留失效代理设置
                let _ = tauri::async_runtime::block_on(async {
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(3), app::shutdown())
                            .await;
                });
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        // 单实例：重复启动时唤起已有窗口并退出新进程，
        // 同时避免两个实例争用同一 WebView2 数据目录导致 0x800700AA 崩溃
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();
            event::init(&handle);
            log_info!("DevSidecar (Tauri) 启动中……");

            // 托盘
            if let Err(e) = build_tray(&handle) {
                log_warn!("创建托盘图标失败: {}", e);
            }

            let async_handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = app::init().await {
                    log_error!("初始化失败: {}", e);
                    event::emit_error("初始化失败", &e.to_string());
                } else {
                    log_info!("初始化完成");
                    // 按已保存的窗口尺寸恢复主窗口（未自定义时为默认值，与 conf 尺寸一致）
                    if let Err(e) = commands::apply_window_size(async_handle.clone()) {
                        log_warn!("恢复窗口尺寸失败: {}", e);
                    }
                }
                let _ = async_handle;
            });

            // 流量统计
            tauri::async_runtime::spawn(async move {
                event::traffic().monitor().await;
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_config,
            commands::get_config_by_path,
            commands::save_config,
            commands::reset_default,
            commands::remove_user_config,
            commands::download_remote_config,
            commands::start_server,
            commands::stop_server,
            commands::start_acceleration,
            commands::stop_acceleration,
            commands::repair_residual_config,
            commands::restart_server,
            commands::server_status,
            commands::app_status,
            commands::open_path,
            commands::open_url,
            commands::get_log_status,
            commands::set_log_disabled,
            commands::shutdown,
            commands::execute_close,
            commands::apply_window_size,
            commands::start_proxy,
            commands::stop_proxy,
            commands::is_ca_exists,
            commands::can_trust_ca,
            commands::get_ca_cert_path,
            commands::get_user_base_path,
            commands::setup_ca,
            commands::enable_plugin,
            commands::disable_plugin,
            commands::plugin_status,
            commands::speed_test,
            commands::traffic_stats,
            commands::reset_traffic,
            commands::dns_providers,
            commands::network_check,
            commands::app_version,
            commands::npm_get_registry,
            commands::get_log_dir,
        ])
        .build(tauri::generate_context!())
        .expect("创建 Tauri 应用失败");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::WindowEvent { label, event, .. } = event {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // 关闭行为由 app.closeAction 决定：ask=每次询问（默认），exit=直接退出，hide=最小化到托盘
                let close_action = crate::app::config()
                    .get()
                    .pointer("/app/closeAction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ask")
                    .to_string();
                // 先拦下关闭，保证清理逻辑有机会执行
                api.prevent_close();
                match close_action.as_str() {
                    "exit" => {
                        let handle = app_handle.clone();
                        tauri::async_runtime::spawn(async move {
                            crate::app::shutdown().await;
                            handle.exit(0);
                        });
                    }
                    "hide" => {
                        if let Some(window) = app_handle.get_webview_window(&label) {
                            let _ = window.hide();
                        }
                    }
                    // 每次询问：交由前端弹窗，用户选择后调用 execute_close 执行
                    _ => {
                        let _ = app_handle.emit("close-requested", &label);
                    }
                }
            }
        }
    });
}

/// 打开主窗口（供前端/托盘调用）
pub fn _open_main(app: &tauri::AppHandle) {
    if app.get_webview_window("main").is_none() {
        let _ = WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
            .title("DevSidecar")
            .inner_size(980.0, 700.0)
            .build();
    }
}
