//! 真实站点连通性验收（默认忽略，避免脱网环境误报）。
//! 通过新启动的代理 CONNECT 隧道访问微软登录与 npm registry，
//! 验证默认 `intercepts-only` 路径不会被 MITM/证书/死端口阻断。
//!
//! 运行：cargo test --test real_network -- --ignored --nocapture

use dev_sidecar_tauri_lib::dns::{init_dns, DnsConfig};
use dev_sidecar_tauri_lib::matcher::domain_map_regexply;
use dev_sidecar_tauri_lib::proxy::{ProxyServer, ServerOptions};
use std::sync::Arc;

fn options(https_port: u16) -> Arc<ServerOptions> {
    let dns_map = Arc::new(init_dns(
        &serde_json::json!({}),
        Arc::new(domain_map_regexply(None)),
    ));
    Arc::new(ServerOptions {
        host: "127.0.0.1".into(),
        port: https_port,
        dns_config: DnsConfig {
            pre_set_ip_list: Arc::new(domain_map_regexply(None)),
            dns_map: dns_map.clone(),
            mapping: Arc::new(domain_map_regexply(None)),
            family_mapping: Some(Arc::new(domain_map_regexply(None))),
        },
        setting: serde_json::json!({}),
        intercepts: Arc::new(domain_map_regexply(None)),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    })
}

#[tokio::test]
#[ignore = "需要外网；手动执行真实链路验收"]
async fn microsoft_login_and_npm_registry_reachable_through_proxy() {
    let https_port = 35181u16;
    let http_port = https_port - 1;
    let server = ProxyServer::start(options(https_port))
        .await
        .expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{http_port}")).expect("构造代理失败"))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("构造 HTTP 客户端失败");

    let targets = [
        (
            "microsoft-login",
            "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fv2.0%2Fauthorize",
        ),
        ("npm-registry", "https://registry.npmjs.org/-/ping"),
    ];
    for (name, url) in targets {
        let resp = client
            .get(url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("{name} 请求失败: {e}"));
        let status = resp.status();
        assert!(
            !matches!(status.as_u16(), 502 | 503 | 504),
            "{name} 经代理返回网关错误: {status}"
        );
        println!("{name}: {status}");
    }

    server.stop().await;
}

/// 真实 npm 客户端验收：临时 userconfig + 合并 CA bundle + strict-ssl，
/// 经代理执行 `npm view`。验证 npm 不会因 cafile 只含私有 CA 或死代理失败。
#[tokio::test]
#[ignore = "需要外网与已安装 npm；手动执行真实链路验收"]
async fn npm_client_works_through_proxy_with_merged_ca_bundle() {
    let https_port = 35183u16;
    let http_port = https_port - 1;
    let server = ProxyServer::start(options(https_port))
        .await
        .expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let user_home = std::env::var("USERPROFILE").expect("缺少 USERPROFILE");
    let bundle = std::path::Path::new(&user_home)
        .join(".dev-sidecar")
        .join("dev-sidecar.ca-bundle.crt");
    assert!(bundle.exists(), "缺少合并 CA bundle: {}", bundle.display());

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("real-npm");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let npmrc = root.join("user.npmrc");
    std::fs::write(
        &npmrc,
        format!(
            "registry=https://registry.npmjs.org/\nstrict-ssl=true\ncafile={}\n",
            bundle
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/")
        ),
    )
    .unwrap();

    let output = tokio::process::Command::new("cmd")
        .args([
            "/C",
            "npm",
            "view",
            "left-pad@1.3.0",
            "version",
            "--userconfig",
            &npmrc.to_string_lossy(),
            "--cache",
            &root.join("cache").to_string_lossy(),
            "--no-audit",
            "--no-fund",
        ])
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{http_port}"))
        .env("HTTP_PROXY", format!("http://127.0.0.1:{http_port}"))
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("npm_config_proxy")
        .env_remove("npm_config_https_proxy")
        .env_remove("npm_config_cafile")
        .env_remove("npm_config_registry")
        .output()
        .await
        .expect("执行 npm 失败");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "npm 经代理失败\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("1.3.0"), "npm 输出异常: {stdout}");
    println!("npm view: {}", stdout.trim());

    let _ = std::fs::remove_dir_all(&root);
    server.stop().await;
}
