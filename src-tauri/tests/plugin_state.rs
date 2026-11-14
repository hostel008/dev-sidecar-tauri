//! 插件开关一致性回归：`plugin.<name>.enabled` 必须由后端按运行时真实状态回写，
//! 否则插件页开关（配置）与状态标签（运行时）会长期不一致。
//! 使用临时 DEV_SIDECAR_HOME + 假 git，不触碰真实用户配置与真实 git 配置。
//!
//! 说明：`DEV_SIDECAR_HOME` 直接就是 `.dev-sidecar` 目录本身；
//! 且 AppState/config 是进程级单例，所以所有场景放在同一个用例里串行验证。

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};

fn write_fake_git(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let js = dir.join("fake-git.cjs");
    std::fs::write(
        &js,
        r#"
const fs = require('fs');
const args = process.argv.slice(2);
const file = process.env.FAKE_GIT_CONFIG;
if (args[0] !== 'config' || args[1] !== '--global') process.exit(5);
const positional = args.slice(2);
function read() {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/);
}
function find(key) {
  let found = null;
  for (const line of read()) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const i = t.indexOf('=');
    if (i >= 0 && t.slice(0, i).trim() === key) found = t.slice(i + 1).trim();
  }
  return found;
}
function write(key, value) {
  const lines = read().filter(line => {
    const t = line.trim();
    const i = t.indexOf('=');
    return !(i >= 0 && t.slice(0, i).trim() === key);
  });
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  lines.push(key + '=' + value);
  fs.writeFileSync(file, lines.join('\n') + '\n');
}
function remove(key) {
  const lines = read().filter(line => {
    const t = line.trim();
    const i = t.indexOf('=');
    return !(i >= 0 && t.slice(0, i).trim() === key);
  });
  fs.writeFileSync(file, lines.join('\n'));
}
if (positional[0] === '--get' || positional[0] === '--get-all') {
  const v = find(positional[1]);
  if (v === null) process.exit(1);
  console.log(v);
  process.exit(0);
}
if (positional[0] === '--unset') { remove(positional[1]); process.exit(0); }
write(positional[0], positional[1]);
process.exit(0);
"#,
    )
    .unwrap();
    let cmd = dir.join("git.cmd");
    std::fs::write(&cmd, "@echo off\r\nnode \"%~dp0fake-git.cjs\" %*\r\n").unwrap();
    cmd.to_string_lossy().to_string()
}

fn enabled_on_disk(base: &Path, plugin: &str) -> bool {
    let text = std::fs::read_to_string(base.join("config.json")).unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&text).unwrap();
    cfg.pointer(&format!("/plugin/{}/enabled", plugin))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn read_config(base: &Path) -> String {
    std::fs::read_to_string(base.join("config.json")).unwrap()
}

#[tokio::test]
async fn plugin_enabled_config_follows_runtime_state() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("plugin-state-tests")
        .join(format!("state-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let base = root.join("dev-sidecar");
    std::fs::create_dir_all(&base).unwrap();

    let gitconfig = root.join("gitconfig");
    std::fs::write(&gitconfig, "# user config\n[http]\n").unwrap();
    std::env::set_var("FAKE_GIT_CONFIG", &gitconfig);
    std::env::set_var("DEV_SIDECAR_HOME", &base);

    let cmd = write_fake_git(&root.join("bin"));
    // 模拟上次会话遗留：enabled=true，但没有勾选「随应用启动」
    let cfg = serde_json::json!({
        "server": { "enabled": false, "host": "127.0.0.1", "port": 34385 },
        "proxy": { "enabled": false, "proxyHttp": false, "setEnv": false, "setCaBundle": false },
        "plugin": {
            "node": { "enabled": false, "startWithApp": false, "envVariables": {} },
            "git": {
                "enabled": true,
                "startWithApp": false,
                "setting": { "command": cmd, "sslVerify": true }
            },
            "pip": { "enabled": false, "startWithApp": false }
        }
    });
    std::fs::write(
        base.join("config.json"),
        serde_json::to_string_pretty(&cfg).unwrap(),
    )
    .unwrap();

    dev_sidecar_tauri_lib::app::start_server().await.unwrap();

    // 1) 未勾选「随应用启动」的插件启动时不会拉起，残留的 enabled=true 必须清掉，
    //    否则插件页开关会一直显示为「已启用」而实际没生效。
    dev_sidecar_tauri_lib::app::sync_plugin_state_to_config();
    assert!(!dev_sidecar_tauri_lib::app::status_snapshot()["git"]
        .as_bool()
        .unwrap());
    assert!(
        !enabled_on_disk(&base, "git"),
        "未随应用启动的插件启动后应清掉残留的 enabled=true: {}",
        read_config(&base)
    );

    // 2) 启用插件后运行时状态与配置必须同时为真
    dev_sidecar_tauri_lib::app::enable_plugin("git")
        .await
        .unwrap();
    assert!(dev_sidecar_tauri_lib::app::status_snapshot()["git"]
        .as_bool()
        .unwrap());
    assert!(
        enabled_on_disk(&base, "git"),
        "启用插件后配置里的 enabled 未同步: {}",
        read_config(&base)
    );

    // 3) 停止服务会撤销活动插件：运行时与配置必须同时回到 false
    dev_sidecar_tauri_lib::app::stop_server().await.unwrap();
    assert!(!dev_sidecar_tauri_lib::app::status_snapshot()["git"]
        .as_bool()
        .unwrap());
    assert!(
        !enabled_on_disk(&base, "git"),
        "停止服务后配置里的 enabled 仍为 true，会与状态标签不一致: {}",
        read_config(&base)
    );

    let _ = std::fs::remove_dir_all(root);
}
