//! 协议升级（WebSocket）隧道测试：明文代理路径下请求带 Upgrade 头，
//! 上游回 101 后代理应透传响应头并转为双向隧道

use dev_sidecar_tauri_lib::dns::{init_dns, DnsConfig};
use dev_sidecar_tauri_lib::matcher::domain_map_regexply;
use dev_sidecar_tauri_lib::proxy::{ProxyServer, ServerOptions};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 升级 echo 源站：回 101 后把收到的字节原样回显
async fn start_upgrade_origin(listener: TcpListener) {
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // 读完整请求头
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match socket.read(&mut byte).await {
                        Ok(0) => return,
                        Ok(_) => {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
                if socket.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // 隧道阶段：原样回显
                let mut buf = [0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
}

/// 读取以 \r\n\r\n 结束的响应头
async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut byte)).await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            _ => break,
        }
    }
    head
}

#[tokio::test]
async fn proxy_tunnels_upgrade() {
    let origin_port = 18083u16;
    let https_port = 34187u16;

    let listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("源站端口绑定失败");
    start_upgrade_origin(listener).await;

    let pre_set_ip_list: serde_json::Value = serde_json::json!({
        "ws.test": { "127.0.0.1": true }
    });
    let preset_map = Arc::new(domain_map_regexply(Some(&pre_set_ip_list)));
    let dns_map = Arc::new(init_dns(&serde_json::json!({}), preset_map.clone()));

    let opts = Arc::new(ServerOptions {
        host: "127.0.0.1".to_string(),
        port: https_port,
        dns_config: DnsConfig {
            pre_set_ip_list: preset_map.clone(),
            dns_map: dns_map.clone(),
            mapping: Arc::new(domain_map_regexply(None)),
            family_mapping: Some(Arc::new(domain_map_regexply(None))),
        },
        setting: serde_json::json!({ "defaultTimeout": 10000 }),
        intercepts: Arc::new(domain_map_regexply(None)),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    });

    let _server = ProxyServer::start(opts).await.expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 经代理（HTTP 端口）发起升级请求
    let mut stream = TcpStream::connect(("127.0.0.1", https_port - 1))
        .await
        .expect("连接代理失败");
    let req = format!(
        "GET http://ws.test:{}/chat HTTP/1.1\r\nHost: ws.test:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        origin_port, origin_port
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    // 1) 应收到 101 响应
    let head = read_head(&mut stream).await;
    let head_text = String::from_utf8_lossy(&head).to_string();
    assert!(
        head_text.contains("101"),
        "期望 101 升级响应: {}",
        head_text
    );
    assert!(
        head_text.to_lowercase().contains("upgrade: websocket"),
        "升级头应被透传: {}",
        head_text
    );

    // 2) 隧道内双向透传：发送的数据应被回显
    let payload = b"hello-tunnel-payload";
    stream.write_all(payload).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("隧道回显超时")
        .expect("隧道读取失败");
    assert_eq!(&buf[..n], payload, "隧道内数据应原样回显");

    // 3) 再来一轮，验证隧道持续可用
    let payload2 = b"second-round";
    stream.write_all(payload2).await.unwrap();
    let mut buf2 = [0u8; 64];
    let n2 = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf2))
        .await
        .expect("隧道第二轮回显超时")
        .expect("隧道第二轮读取失败");
    assert_eq!(&buf2[..n2], payload2, "隧道应支持多轮双向传输");
}
