//! 生命周期回归：服务停止后必须立即释放端口，且可再次启动。
//! 使用独立 DEV_SIDECAR_HOME，绝不读取或改写真实用户配置与系统代理。

use dev_sidecar_tauri_lib::app;
use std::path::PathBuf;

fn test_home() -> PathBuf {
    let home = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join(format!("lifecycle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".dev-sidecar")).unwrap();
    std::fs::write(
        home.join(".dev-sidecar").join("config.json"),
        r#"{
            "server": { "enabled": false, "host": "127.0.0.1", "port": 34281 },
            "proxy": { "enabled": false, "proxyHttp": false, "setEnv": false, "setCaBundle": false },
            "plugin": {
                "node": { "enabled": false, "startWithApp": false },
                "git": { "enabled": false, "startWithApp": false },
                "pip": { "enabled": false, "startWithApp": false }
            }
        }"#,
    )
    .unwrap();
    home
}

#[tokio::test]
async fn app_server_can_restart_immediately_after_stop() {
    let home = test_home();
    std::env::set_var("DEV_SIDECAR_HOME", &home);

    app::start_server().await.expect("首次启动服务失败");
    assert!(app::status_snapshot()["server"].as_bool().unwrap());

    app::stop_server().await.expect("停止服务失败");
    assert!(!app::status_snapshot()["server"].as_bool().unwrap());

    // 停止返回后端口必须已经释放，前端立即开启不能撞上 Address already in use
    app::start_server().await.expect("停止后立即重启失败");
    assert!(app::status_snapshot()["server"].as_bool().unwrap());
    app::stop_server().await.expect("再次停止服务失败");

    let _ = std::fs::remove_dir_all(home);
}
