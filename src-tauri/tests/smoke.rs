//! 冒烟测试：启动代理，转发一个本地 HTTP 请求

use dev_sidecar_tauri_lib::dns::{init_dns, DnsConfig};
use dev_sidecar_tauri_lib::matcher::domain_map_regexply;
use dev_sidecar_tauri_lib::proxy::{ProxyServer, ServerOptions};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// 回显请求体长度的源站（用于验证请求体不会被代理丢弃）
async fn start_echo_origin(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 1024];
                let head_end = loop {
                    let n = match socket.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = find_head_end(&buf) {
                        break i;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.eq_ignore_ascii_case("content-length") {
                            v.trim().parse().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let mut body = buf[head_end..].to_vec();
                while body.len() < len {
                    match socket.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&tmp[..n]),
                    }
                }
                let payload = format!("len={}", body.len());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn test_options(https_port: u16) -> Arc<ServerOptions> {
    let dns_map = Arc::new(init_dns(
        &serde_json::json!({}),
        Arc::new(domain_map_regexply(None)),
    ));
    Arc::new(ServerOptions {
        host: "127.0.0.1".to_string(),
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

async fn start_origin_server(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let body = "ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
}

/// 无正文响应源站：支持 keep-alive 上连续处理 HEAD、204、304 和普通 GET
async fn start_bodyless_origin(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        match socket.read(&mut byte).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                head.push(byte[0]);
                                if head.ends_with(b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&head);
                    let path = text
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("");
                    let (status, body) = match path {
                        "/head" => ("200 OK", ""),
                        "/204" => ("204 No Content", ""),
                        "/304" => ("304 Not Modified", ""),
                        _ => ("200 OK", "ok"),
                    };
                    let length = if body.is_empty() {
                        String::new()
                    } else {
                        format!("Content-Length: {}\r\n", body.len())
                    };
                    let resp = format!(
                        "HTTP/1.1 {}\r\n{}Connection: keep-alive\r\n\r\n{}",
                        status, length, body
                    );
                    if socket.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

/// 回归：HEAD/204/304 无 Content-Length 时不得写 chunked 终止块，
/// 同一客户端连接上的下一个响应必须紧接第一段响应头。
#[tokio::test]
async fn proxy_bodyless_response_does_not_pollute_keep_alive() {
    let origin_port = 18088u16;
    let https_port = 33186u16;
    start_bodyless_origin(origin_port).await;

    let _server = ProxyServer::start(test_options(https_port))
        .await
        .expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    for (method, path, status) in [
        ("HEAD", "/head", "200"),
        ("GET", "/204", "204"),
        ("GET", "/304", "304"),
    ] {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", https_port - 1))
            .await
            .expect("连接代理失败");
        let first = format!(
            "{method} http://127.0.0.1:{origin_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
        );
        let second = format!(
            "GET http://127.0.0.1:{origin_port}/ok HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(format!("{first}{second}").as_bytes())
            .await
            .unwrap();

        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.ends_with(b"ok") {
                        break;
                    }
                }
            }
        }

        let first_end = find_head_end(&out).unwrap_or_else(|| {
            panic!(
                "{} {} 未收到完整响应头: {}",
                method,
                path,
                String::from_utf8_lossy(&out)
            )
        });
        let text = String::from_utf8_lossy(&out);
        assert!(
            text.starts_with(&format!("HTTP/1.1 {status}")),
            "{} {} 首个状态码不符: {}",
            method,
            path,
            text
        );
        assert!(
            out[first_end..].starts_with(b"HTTP/1.1 200"),
            "{} {} 与后续响应之间存在多余字节: {:?}",
            method,
            path,
            String::from_utf8_lossy(&out[first_end..])
        );
        assert_eq!(
            text.matches("HTTP/1.1 ").count(),
            2,
            "{} {} 应收到两个完整响应: {}",
            method,
            path,
            text
        );
    }
}

#[tokio::test]
async fn proxy_forwards_http_request() {
    let origin_port = 18081u16;
    let https_port = 33181u16;
    let http_port = https_port - 1;

    start_origin_server(origin_port).await;

    let dns_map = Arc::new(init_dns(
        &serde_json::json!({}),
        Arc::new(domain_map_regexply(None)),
    ));

    let opts = Arc::new(ServerOptions {
        host: "127.0.0.1".to_string(),
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
    });

    let _server = ProxyServer::start(opts).await.expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
        .await
        .expect("连接代理失败");
    let req = format!(
        "GET http://127.0.0.1:{}/hello HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin_port, origin_port
    );
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(4).any(|w| w == b"\r\n\r\n") && out.ends_with(b"ok") {
                    break;
                }
            }
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    println!("响应:\n{}", text);
    assert!(text.starts_with("HTTP/1.1 200"), "期望 200 响应: {}", text);
    assert!(text.ends_with("ok"), "期望响应体: {}", text);
}

/// 回归测试：请求头与请求体在同一 TCP 段到达时，请求体不能被丢弃；
/// 且同一连接上流水线发送的第二个请求必须被正确处理（BufReader 复用）。
#[tokio::test]
async fn proxy_forwards_post_body_and_pipelined_request() {
    let origin_port = 18082u16;
    let https_port = 33183u16;
    let http_port = https_port - 1;

    start_echo_origin(origin_port).await;

    let _server = ProxyServer::start(test_options(https_port))
        .await
        .expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
        .await
        .expect("连接代理失败");

    let body = "0123456789";
    let req1 = format!(
        "POST http://127.0.0.1:{}/p HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
        origin_port,
        origin_port,
        body.len(),
        body
    );
    let req2 = format!(
        "POST http://127.0.0.1:{}/p HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        origin_port,
        origin_port,
        body.len(),
        body
    );

    // 两个请求一次性写入，模拟客户端把请求头+请求体放在同一段中发送
    stream
        .write_all(format!("{}{}", req1, req2).as_bytes())
        .await
        .unwrap();

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&out);
                if text.matches("len=10").count() >= 2 {
                    break;
                }
            }
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    println!("响应:\n{}", text);
    assert_eq!(
        text.matches("len=10").count(),
        2,
        "两个请求体都应完整转发（实际响应: {}）",
        text
    );
    // 头名大小写不敏感（hyper 读取上游响应头时会转小写）
    let lower = text.to_lowercase();
    assert!(
        lower.contains("set-cookie: a=1") && lower.contains("set-cookie: b=2"),
        "同名多值响应头不应被合并丢失: {}",
        text
    );
}

/// 回归：停止后端口必须在下一次启动前真正释放，否则“停止立即再开启”会
/// 报 Address already in use，前端表现为加速按钮失效。
#[tokio::test]
async fn proxy_stop_releases_ports_for_immediate_restart() {
    let https_port = 33188u16;

    let first = ProxyServer::start(test_options(https_port))
        .await
        .expect("首次启动代理失败");
    first.stop().await;

    let second = ProxyServer::start(test_options(https_port))
        .await
        .expect("停止后立即重启代理失败");
    second.stop().await;
}
