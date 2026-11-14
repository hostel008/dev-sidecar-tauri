//! 拦截器冒烟测试：success / abort / redirect / OPTIONS / cacheRequest

use dev_sidecar_tauri_lib::dns::{init_dns, DnsConfig};
use dev_sidecar_tauri_lib::matcher::domain_map_regexply;
use dev_sidecar_tauri_lib::proxy::{ProxyServer, ServerOptions};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start_proxy(https_port: u16, intercepts: serde_json::Value) -> ProxyServer {
    let dns_map = Arc::new(init_dns(
        &serde_json::json!({}),
        Arc::new(domain_map_regexply(None)),
    ));
    let opts = Arc::new(ServerOptions {
        host: "127.0.0.1".to_string(),
        port: https_port,
        dns_config: DnsConfig {
            pre_set_ip_list: Arc::new(domain_map_regexply(None)),
            dns_map,
            mapping: Arc::new(domain_map_regexply(None)),
            family_mapping: Some(Arc::new(domain_map_regexply(None))),
        },
        setting: serde_json::json!({ "defaultTimeout": 5000 }),
        intercepts: Arc::new(domain_map_regexply(Some(&intercepts))),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    });
    ProxyServer::start(opts).await.expect("启动代理失败")
}

/// 通过 HTTP 端口发送绝对 URI 请求
async fn request(port: u16, raw: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[tokio::test]
async fn intercept_success_and_abort() {
    let https_port = 35181u16;
    let _server = start_proxy(
        https_port,
        serde_json::json!({
            "test-success.local": { ".*": { "success": true } },
            "test-abort.local": { ".*": { "abort": true } }
        }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let ok = request(
        https_port - 1,
        "GET http://test-success.local/hello HTTP/1.1\r\nHost: test-success.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    println!("success 拦截响应:\n{}", ok);
    assert!(ok.starts_with("HTTP/1.1 200"), "期望 200: {}", ok);
    assert!(
        ok.to_lowercase().contains("ds-interceptor: success"),
        "缺少 DS-Interceptor: {}",
        ok
    );

    let abort = request(
        https_port - 1,
        "GET http://test-abort.local/hello HTTP/1.1\r\nHost: test-abort.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    println!("abort 拦截响应:\n{}", abort);
    assert!(abort.starts_with("HTTP/1.1 403"), "期望 403: {}", abort);
}

#[tokio::test]
async fn intercept_redirect() {
    let https_port = 36181u16;
    let _server = start_proxy(
        https_port,
        serde_json::json!({
            "test-redirect.local": {
                "/p/(.*)": { "redirect": "https://example.com/target/${p[1]}" }
            }
        }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let resp = request(
        https_port - 1,
        "GET http://test-redirect.local/p/abc HTTP/1.1\r\nHost: test-redirect.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    println!("redirect 拦截响应:\n{}", resp);
    assert!(resp.starts_with("HTTP/1.1 302"), "期望 302: {}", resp);
    assert!(
        resp.to_lowercase()
            .contains("location: https://example.com/target/abc"),
        "Location 头不正确: {}",
        resp
    );
}

#[tokio::test]
async fn intercept_options_preflight() {
    let https_port = 37181u16;
    let _server = start_proxy(
        https_port,
        serde_json::json!({
            "test-options.local": { ".*": { "options": true, "optionsMaxAge": 600 } }
        }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let resp = request(
        https_port - 1,
        "OPTIONS http://test-options.local/api HTTP/1.1\r\nHost: test-options.local\r\nOrigin: https://example.com\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n",
    )
    .await;
    println!("OPTIONS 拦截响应:\n{}", resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "期望 200: {}", resp);
    assert!(
        resp.to_lowercase()
            .contains("access-control-allow-origin: https://example.com"),
        "缺少 CORS 头: {}",
        resp
    );
    assert!(
        resp.to_lowercase().contains("access-control-max-age: 600"),
        "缺少 max-age: {}",
        resp
    );
}
