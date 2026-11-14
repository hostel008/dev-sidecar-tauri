//! Windows 上验证 Git/PIP 全局配置事务：快照、读回、失败回滚、外部改动保护。
//! 通过临时 DEV_SIDECAR_HOME 与假命令执行，不触碰真实 git/pip 配置。

#![cfg(target_os = "windows")]

use dev_sidecar_tauri_lib::plugin::{GitPlugin, PipPlugin};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn write_fake_command(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let js = dir.join("fake-config.cjs");
    std::fs::write(
        &js,
        r#"
const fs = require('fs');
const args = process.argv.slice(2);
// git config 一定带 --global；pip config 不带。按参数判定，避免测试同时恢复
// Git 与 PIP 时依赖进程级 FAKE_MODE。
const mode = args[1] === '--global' ? 'git' : 'pip';
const file = process.env[mode === 'git' ? 'FAKE_GIT_CONFIG' : 'FAKE_PIP_CONFIG'];
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
function fail(action, key) {
  return process.env.FAKE_FAIL_KEY === key && process.env.FAKE_FAIL_ACTION === action;
}
let action, key, value;
if (mode === 'git') {
  if (args[0] !== 'config' || args[1] !== '--global') process.exit(5);
  const positional = args.slice(2);
  if (positional[0] === '--get' || positional[0] === '--get-all') { action = 'get'; key = positional[1]; }
  else if (positional[0] === '--unset') { action = 'unset'; key = positional[1]; }
  else { action = 'set'; key = positional[0]; value = positional[1]; }
} else {
  if (args[0] !== 'config') process.exit(5);
  action = args[1]; key = args[2]; value = args[3];
}
if (action === 'get') {
  const v = find(key);
  if (v === null) {
    if (mode === 'pip') console.error('ERROR: No such key - ' + key);
    process.exit(1);
  }
  console.log(v);
  process.exit(0);
}
if (fail(action, key)) {
  console.error('injected failure for ' + action + ' ' + key);
  process.exit(3);
}
if (action === 'set') write(key, value);
else if (action === 'unset') remove(key);
else process.exit(6);
"#,
    )
    .unwrap();
    let cmd = dir.join("fake-config.cmd");
    std::fs::write(&cmd, "@echo off\r\nnode \"%~dp0fake-config.cjs\" %*\r\n").unwrap();
    cmd.to_string_lossy().to_string()
}

fn setup(name: &str, initial: &str) -> (PathBuf, String, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("git-pip-tests")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("DEV_SIDECAR_HOME", &home);
    let config_file = root.join("global.conf");
    std::fs::write(&config_file, initial).unwrap();
    std::env::set_var("FAKE_GIT_CONFIG", &config_file);
    std::env::set_var("FAKE_PIP_CONFIG", &config_file);
    std::env::remove_var("FAKE_FAIL_KEY");
    std::env::remove_var("FAKE_FAIL_ACTION");
    let cmd = write_fake_command(&root.join("bin"));
    (root, cmd, config_file)
}

fn git_config(cmd: &str) -> Value {
    json!({
        "plugin": {
            "git": {
                "setting": {
                    "command": cmd,
                    "sslVerify": true,
                    "noProxyUrls": { "https://no-proxy.example": true }
                }
            }
        },
        "server": { "port": 31181, "host": "127.0.0.1" }
    })
}

fn pip_config(cmd: &str) -> Value {
    json!({
        "plugin": {
            "pip": {
                "setting": {
                    "command": cmd,
                    "registry": "https://pypi.tuna.tsinghua.edu.cn/simple",
                    "trustedHost": "pypi.tuna.tsinghua.edu.cn"
                }
            }
        },
        "server": { "port": 31181, "host": "127.0.0.1" }
    })
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap().replace("\r\n", "\n")
}

/// 假命令以“删除后追加”的方式写入，行顺序可能变化，比较配置集合。
fn sorted(path: &Path) -> Vec<String> {
    let text = read(path);
    let mut lines: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    lines.sort();
    lines
}

#[tokio::test]
async fn git_configuration_is_transactional_and_restorable() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("FAKE_MODE", "git");
    let (root, cmd, file) = setup(
        "git-restore",
        "http.proxy=http://user:8080\nhttp.sslVerify=false\nhttp.https://no-proxy.example.proxy=http://keep\n",
    );
    let cfg = git_config(&cmd);

    GitPlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();
    let opened = read(&file);
    assert!(opened.contains("http.proxy=http://127.0.0.1:31181"));
    assert!(opened.contains("http.sslVerify=true"));
    assert!(!opened.contains("no-proxy.example"));

    GitPlugin::close_proxy(&cfg).await.unwrap();
    assert_eq!(
        sorted(&file),
        vec![
            "http.https://no-proxy.example.proxy=http://keep".to_string(),
            "http.proxy=http://user:8080".to_string(),
            "http.sslVerify=false".to_string(),
        ]
    );
    assert!(!root.join("home").join("git-managed-state.json").exists());
}

#[tokio::test]
async fn git_external_edit_survives_close() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("FAKE_MODE", "git");
    let (_root, cmd, file) = setup("git-external", "http.proxy=http://user:8080\n");
    let cfg = git_config(&cmd);

    GitPlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();
    std::fs::write(
        &file,
        "http.proxy=http://external:9000\nhttp.sslVerify=true\n",
    )
    .unwrap();
    GitPlugin::close_proxy(&cfg).await.unwrap();
    let closed = read(&file);
    assert!(closed.contains("http.proxy=http://external:9000"));
    // 未被外部修改的键继续按快照恢复
    assert!(!closed.contains("http.sslVerify=true"));
    assert!(!closed.contains("http.https://no-proxy.example.proxy"));
}

#[tokio::test]
async fn git_failed_write_rolls_back_all_applied_keys() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("FAKE_MODE", "git");
    let (root, cmd, file) = setup(
        "git-rollback",
        "http.proxy=http://user:8080\nhttp.sslVerify=false\n",
    );
    let cfg = git_config(&cmd);
    std::env::set_var("FAKE_FAIL_KEY", "http.sslVerify");
    std::env::set_var("FAKE_FAIL_ACTION", "set");

    let err = GitPlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("已回滚"), "{err}");
    assert_eq!(
        sorted(&file),
        vec![
            "http.proxy=http://user:8080".to_string(),
            "http.sslVerify=false".to_string(),
        ]
    );
    assert!(!root.join("home").join("git-managed-state.json").exists());
}

#[tokio::test]
async fn git_legacy_cleanup_keeps_user_local_proxy() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("FAKE_MODE", "git");
    let (_root, cmd, file) = setup("git-legacy-keep", "http.proxy=http://127.0.0.1:7890\n");
    let cfg = git_config(&cmd);
    GitPlugin::close_proxy(&cfg).await.unwrap();
    assert!(read(&file).contains("http.proxy=http://127.0.0.1:7890"));

    std::fs::write(&file, "http.proxy=http://127.0.0.1:31181\n").unwrap();
    GitPlugin::close_proxy(&cfg).await.unwrap();
    assert!(!read(&file).contains("http.proxy"));
}

#[tokio::test]
async fn pip_configuration_is_transactional_and_restorable() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("FAKE_MODE", "pip");
    let (root, cmd, file) = setup(
        "pip-restore",
        "global.index-url=https://private.example/simple\nglobal.trusted-host=private.example\n",
    );
    let cfg = pip_config(&cmd);

    PipPlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();
    let opened = read(&file);
    assert!(opened.contains("global.index-url=https://pypi.tuna.tsinghua.edu.cn/simple"));
    assert!(opened.contains("global.proxy=http://127.0.0.1:31181"));

    PipPlugin::close_proxy(&cfg).await.unwrap();
    assert_eq!(
        read(&file),
        "global.index-url=https://private.example/simple\nglobal.trusted-host=private.example\n"
    );
    assert!(!root.join("home").join("pip-managed-state.json").exists());
}

#[tokio::test]
async fn pip_failed_write_rolls_back_without_losing_user_registry() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("FAKE_MODE", "pip");
    let (root, cmd, file) = setup(
        "pip-rollback",
        "global.index-url=https://private.example/simple\n",
    );
    let cfg = pip_config(&cmd);
    std::env::set_var("FAKE_FAIL_KEY", "global.trusted-host");
    std::env::set_var("FAKE_FAIL_ACTION", "set");

    let err = PipPlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("已回滚"), "{err}");
    assert_eq!(
        read(&file),
        "global.index-url=https://private.example/simple\n"
    );
    assert!(!root.join("home").join("pip-managed-state.json").exists());
}

#[tokio::test]
async fn startup_recovery_restores_git_and_pip_from_snapshots_without_journal() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("FAKE_MODE", "git");
    let (root, cmd, git_file) = setup(
        "startup-recovery",
        "http.proxy=http://user:8080\nhttp.sslVerify=false\n",
    );
    let home = root.join("home");
    let pip_file = root.join("pip.conf");
    std::fs::write(
        &pip_file,
        "global.index-url=https://private.example/simple\n",
    )
    .unwrap();
    let cfg = json!({
        "plugin": {
            "git": { "setting": { "command": cmd, "sslVerify": true, "noProxyUrls": {} } },
            "pip": { "setting": {
                "command": cmd,
                "registry": "https://pypi.org/simple/",
                "trustedHost": "pypi.org"
            } }
        },
        "server": { "host": "127.0.0.1", "port": 41981 },
        "proxy": { "enabled": false, "proxyHttp": false, "setEnv": false, "setCaBundle": false }
    });
    std::fs::write(
        home.join("config.json"),
        serde_json::to_string(&cfg).unwrap(),
    )
    .unwrap();

    // 先模拟上次运行写入的外部配置，且故意不写 runtime journal。
    GitPlugin::open_proxy(&cfg, "127.0.0.1", 41981)
        .await
        .unwrap();
    std::env::set_var("FAKE_PIP_CONFIG", &pip_file);
    std::env::set_var("FAKE_MODE", "pip");
    PipPlugin::open_proxy(&cfg, "127.0.0.1", 41981)
        .await
        .unwrap();
    assert!(home.join("git-managed-state.json").exists());
    assert!(home.join("pip-managed-state.json").exists());

    dev_sidecar_tauri_lib::app::recover_previous_runtime()
        .await
        .expect("启动恢复失败");

    assert_eq!(
        sorted(&git_file),
        vec![
            "http.proxy=http://user:8080".to_string(),
            "http.sslVerify=false".to_string(),
        ]
    );
    assert_eq!(
        sorted(&pip_file),
        vec!["global.index-url=https://private.example/simple".to_string()]
    );
    assert!(!home.join("git-managed-state.json").exists());
    assert!(!home.join("pip-managed-state.json").exists());
    let _ = std::fs::remove_dir_all(root);
}
