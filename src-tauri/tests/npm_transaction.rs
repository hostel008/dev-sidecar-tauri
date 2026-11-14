//! Windows 上验证 npm 配置事务：原始值快照、逐键读回、失败回滚、崩溃恢复。
//! 使用临时 DEV_SIDECAR_HOME 和假的 npm 可执行文件，不触碰真实用户配置。

#![cfg(target_os = "windows")]

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// 这些用例通过进程级环境变量指定临时 home / 假 npm，必须串行执行。
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn write_fake_npm(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let js = dir.join("fake-npm.cjs");
    std::fs::write(
        &js,
        r#"
const fs = require('fs');
const args = process.argv.slice(2);
const file = process.env.FAKE_NPMRC;
function read() {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/);
}
function find(key) {
  let found = null;
  for (const line of read()) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith(';')) continue;
    const i = t.indexOf('=');
    if (i < 0) continue;
    if (t.slice(0, i).trim().toLowerCase() === key.toLowerCase()) found = t.slice(i + 1).trim();
  }
  return found;
}
function write(key, value) {
  const lines = read().filter(line => {
    const t = line.trim();
    const i = t.indexOf('=');
    return !(i >= 0 && t.slice(0, i).trim().toLowerCase() === key.toLowerCase());
  });
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  lines.push(key + '=' + value);
  fs.writeFileSync(file, lines.join('\n') + '\n');
}
function remove(key) {
  const lines = read().filter(line => {
    const t = line.trim();
    const i = t.indexOf('=');
    return !(i >= 0 && t.slice(0, i).trim().toLowerCase() === key.toLowerCase());
  });
  fs.writeFileSync(file, lines.join('\n'));
}
const loc = args.indexOf('--location=user');
const positional = loc >= 0 ? args.slice(0, loc) : args;
if (positional[0] !== 'config') process.exit(4);
const action = positional[1];
if (action === 'get') {
  if (positional[2] === 'userconfig') console.log(file);
  else {
    const v = find(positional[2]);
    console.log(v === null ? 'null' : v);
  }
  process.exit(0);
}
if (action === 'set') {
  const pairs = positional.slice(2);
  for (let i = 0; i < pairs.length; i += 2) {
    if (process.env.FAKE_NPM_FAIL_KEY && pairs[i] === process.env.FAKE_NPM_FAIL_KEY) {
      console.error('injected failure for ' + pairs[i]);
      process.exit(3);
    }
    write(pairs[i], pairs[i + 1]);
  }
  process.exit(0);
}
if (action === 'delete') {
  for (const key of positional.slice(2)) remove(key);
  process.exit(0);
}
process.exit(5);
"#,
    )
    .unwrap();
    let cmd = dir.join("npm.cmd");
    std::fs::write(
        &cmd,
        format!(
            "@echo off\r\nnode \"%~dp0{fake}\" %*\r\n",
            fake = "fake-npm.cjs"
        ),
    )
    .unwrap();
    cmd.to_string_lossy().to_string()
}

fn setup(name: &str, npmrc: &str) -> (PathBuf, String) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("npm-transaction-tests")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("DEV_SIDECAR_HOME", &home);
    let userconfig = root.join("user.npmrc");
    std::fs::write(&userconfig, npmrc).unwrap();
    std::env::set_var("FAKE_NPMRC", &userconfig);
    std::env::remove_var("FAKE_NPM_FAIL_KEY");
    let cmd = write_fake_npm(&root.join("bin"));
    (root, cmd)
}

fn config(cmd: &str) -> Value {
    json!({
        "plugin": {
            "node": {
                "setting": {
                    "command": cmd,
                    "registry": "https://registry.npmmirror.com",
                    "strict-ssl": true,
                    "cafile": false,
                    "NODE_EXTRA_CA_CERTS": false
                },
                "variables": { "custom": "new" },
                "envVariables": {}
            }
        },
        "server": { "setting": { "rootCaFile": { "certPath": "" } } }
    })
}

#[tokio::test]
async fn npm_configuration_is_transactional_and_restorable() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_root, cmd) = setup(
        "restore",
        "# keep this comment\nregistry=https://private.example/\nstrict-ssl=false\ncustom=old\n",
    );
    let cfg = config(&cmd);

    dev_sidecar_tauri_lib::plugin::NodePlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();
    let userconfig = std::env::var("FAKE_NPMRC").unwrap();
    let active = std::fs::read_to_string(&userconfig).unwrap();
    assert!(active.contains("registry=https://registry.npmmirror.com"));
    assert!(active.contains("proxy=http://127.0.0.1:31181"));
    assert!(active.contains("https-proxy=http://127.0.0.1:31181"));
    assert!(active.contains("strict-ssl=true"));
    assert!(active.contains("custom=new"));

    dev_sidecar_tauri_lib::plugin::NodePlugin::close_proxy(&cfg)
        .await
        .unwrap();
    let restored = std::fs::read_to_string(&userconfig).unwrap();
    assert!(restored.contains("# keep this comment"));
    assert!(restored.contains("registry=https://private.example/"));
    assert!(restored.contains("strict-ssl=false"));
    assert!(restored.contains("custom=old"));
    assert!(!restored.contains("proxy="));
    assert!(!restored.contains("https-proxy="));
    assert!(!dev_sidecar_tauri_lib::util::paths::npm_managed_state_path().exists());
}

#[tokio::test]
async fn npm_partial_write_failure_rolls_back_every_key() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_root, cmd) = setup("rollback", "registry=https://private.example/\n");
    std::env::set_var("FAKE_NPM_FAIL_KEY", "proxy");
    let cfg = config(&cmd);

    let err = dev_sidecar_tauri_lib::plugin::NodePlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("已回滚"), "{err}");
    let userconfig = std::env::var("FAKE_NPMRC").unwrap();
    let restored = std::fs::read_to_string(&userconfig).unwrap();
    assert_eq!(restored, "registry=https://private.example/\n");
    assert!(!dev_sidecar_tauri_lib::util::paths::npm_managed_state_path().exists());
}

#[tokio::test]
async fn npm_crash_recovery_only_restores_owned_values() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_root, cmd) = setup("recover", "custom=old\n");
    let cfg = config(&cmd);
    dev_sidecar_tauri_lib::plugin::NodePlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();

    // 模拟崩溃：保留 journal 状态，再由下次启动恢复。
    dev_sidecar_tauri_lib::plugin::recover_npm_state(&cfg)
        .await
        .unwrap();
    let userconfig = std::env::var("FAKE_NPMRC").unwrap();
    let restored = std::fs::read_to_string(&userconfig).unwrap();
    assert_eq!(restored, "custom=old\n");
    assert!(!dev_sidecar_tauri_lib::util::paths::npm_managed_state_path().exists());
}

#[tokio::test]
async fn npm_external_edit_is_not_overwritten_on_close() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_root, cmd) = setup("external", "custom=old\n");
    let cfg = config(&cmd);
    dev_sidecar_tauri_lib::plugin::NodePlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();
    let userconfig = std::env::var("FAKE_NPMRC").unwrap();
    let edited = std::fs::read_to_string(&userconfig).unwrap().replace(
        "registry=https://registry.npmmirror.com",
        "registry=https://user-edit.example/",
    );
    std::fs::write(&userconfig, edited).unwrap();

    dev_sidecar_tauri_lib::plugin::NodePlugin::close_proxy(&cfg)
        .await
        .unwrap();
    let result = std::fs::read_to_string(&userconfig).unwrap();
    assert!(result.contains("registry=https://user-edit.example/"));
    assert!(result.contains("custom=old"));
}

/// 审查回归：`cafile` 选项关闭只代表“不替换信任库”，
/// 不能删除用户原有的 cafile（企业根证书），否则开启加速后 npm 反而校验失败。
#[tokio::test]
async fn npm_disabled_cafile_keeps_user_cafile() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_root, cmd) = setup(
        "cafile-keep",
        "registry=https://private.example/\ncafile=C:/corp/root-ca.pem\n",
    );
    let mut cfg = config(&cmd);
    cfg["plugin"]["node"]["setting"]["cafile"] = json!(false);

    dev_sidecar_tauri_lib::plugin::NodePlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();
    let userconfig = std::env::var("FAKE_NPMRC").unwrap();
    let active = std::fs::read_to_string(&userconfig).unwrap();
    assert!(
        active.contains("cafile=C:/corp/root-ca.pem"),
        "用户 cafile 被误删: {active}"
    );

    dev_sidecar_tauri_lib::plugin::NodePlugin::close_proxy(&cfg)
        .await
        .unwrap();
    let restored = std::fs::read_to_string(&userconfig).unwrap();
    assert!(restored.contains("cafile=C:/corp/root-ca.pem"));
    assert!(!restored.contains("proxy="));
}

/// 审查回归：配置里移除某个自定义变量后重新应用，若用户已手动改过该值，
/// 不能用旧快照覆盖用户改动。
#[tokio::test]
async fn npm_stale_key_does_not_overwrite_external_edit() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (_root, cmd) = setup("stale-external", "custom=old\n");
    let mut cfg = config(&cmd);
    cfg["plugin"]["node"]["variables"] = json!({ "custom": "ours" });
    dev_sidecar_tauri_lib::plugin::NodePlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();
    let userconfig = std::env::var("FAKE_NPMRC").unwrap();
    assert!(std::fs::read_to_string(&userconfig)
        .unwrap()
        .contains("custom=ours"));

    // 用户手工改成自己的值，随后配置里去掉该变量并重新应用
    let edited = std::fs::read_to_string(&userconfig)
        .unwrap()
        .replace("custom=ours", "custom=user-edit");
    std::fs::write(&userconfig, edited).unwrap();
    cfg["plugin"]["node"]["variables"] = json!({});
    dev_sidecar_tauri_lib::plugin::NodePlugin::open_proxy(&cfg, "127.0.0.1", 31181)
        .await
        .unwrap();

    let active = std::fs::read_to_string(&userconfig).unwrap();
    assert!(
        active.contains("custom=user-edit"),
        "旧快照覆盖了用户的外部修改: {active}"
    );
    dev_sidecar_tauri_lib::plugin::NodePlugin::close_proxy(&cfg)
        .await
        .unwrap();
}
