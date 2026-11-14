//! MITM 冒烟测试：CONNECT 拦截 → 伪造证书 → 解密 → 转发到 HTTPS 源站

use dev_sidecar_tauri_lib::dns::{init_dns, DnsConfig};
use dev_sidecar_tauri_lib::matcher::domain_map_regexply;
use dev_sidecar_tauri_lib::proxy::{ProxyServer, ServerOptions};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 生成一个自签名的源站证书
fn origin_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost.test".to_string()]).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        "localhost.test".try_into().unwrap(),
    )];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    let cert = params.self_signed(&kp).unwrap();
    (
        cert.der().clone(),
        rustls::pki_types::PrivateKeyDer::try_from(kp.serialize_der()).unwrap(),
    )
}

async fn start_https_origin(listener: TcpListener) {
    let (cert, key) = origin_cert();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let body = "ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
}

#[tokio::test]
async fn proxy_mitm_https_request() {
    let temp = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("ds-mitm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    std::env::set_var("DEV_SIDECAR_HOME", &temp);

    let origin_port = 18443u16;
    let https_port = 34181u16;

    let origin_listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("源站端口绑定失败");
    start_https_origin(origin_listener).await;
    let ca = match dev_sidecar_tauri_lib::app::ensure_ca() {
        Ok(ca) => ca,
        Err(e) => panic!("初始化 CA 失败: {:?}", e),
    };

    let intercepts: serde_json::Value = serde_json::json!({
        "localhost.test": {
            ".*": { "unVerifySsl": true }
        }
    });
    let pre_set_ip_list: serde_json::Value = serde_json::json!({
        "localhost.test": { "127.0.0.1": true }
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
        intercepts: Arc::new(domain_map_regexply(Some(&intercepts))),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    });

    let _server = ProxyServer::start(opts).await.expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 1) 发送 CONNECT
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", https_port))
        .await
        .expect("连接代理失败");
    let connect = format!(
        "CONNECT localhost.test:{} HTTP/1.1\r\nHost: localhost.test:{}\r\n\r\n",
        origin_port, origin_port
    );
    stream.write_all(connect.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut buf = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        head.push(buf[0]);
    }
    assert!(
        String::from_utf8_lossy(&head).contains("200"),
        "CONNECT 未建立: {}",
        String::from_utf8_lossy(&head)
    );

    // 2) 用伪造证书完成 TLS 握手（校验 CA）
    let ca_pem = std::fs::read(dev_sidecar_tauri_lib::util::paths::ca_cert_path()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    let mut parsed = 0usize;
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        roots.add(cert.unwrap()).unwrap();
        parsed += 1;
    }
    println!(
        "解析到 {} 个根证书, PEM 开头: {:?}",
        parsed,
        &String::from_utf8_lossy(&ca_pem)[..40.min(ca_pem.len())]
    );
    assert!(parsed > 0, "未解析到根证书");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let name = rustls::pki_types::ServerName::try_from("localhost.test")
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(name, stream).await.expect("TLS 握手失败");
    let _ = ca;

    // 3) 发起 GET 请求
    tls.write_all(
        format!(
            "GET /hello HTTP/1.1\r\nHost: localhost.test:{}\r\nConnection: close\r\n\r\n",
            origin_port
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if out.ends_with(b"ok") {
                    break;
                }
            }
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    println!("响应:\n{}", text);
    assert!(text.starts_with("HTTP/1.1 200"), "期望 200 响应: {}", text);
    assert!(text.ends_with("ok"), "期望响应体 ok: {}", text);

    let _ = std::fs::remove_dir_all(&temp);
}

/// 连接池复用测试：两次独立请求（相同 host/ip/port）应复用同一上游连接，
/// 源站仅接受 1 条 TCP 连接
#[tokio::test]
async fn proxy_reuses_upstream_connection() {
    let origin_port = 18082u16;
    let https_port = 34185u16;

    let listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("源站端口绑定失败");
    let conn_count = Arc::new(AtomicUsize::new(0));
    {
        let conn_count = conn_count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                conn_count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    // 源站：HTTP/1.1 keep-alive，循环服务同一条连接上的多个请求
                    loop {
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
                        let body = "ok";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        if socket.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
    }

    let pre_set_ip_list: serde_json::Value = serde_json::json!({
        "origin.test": { "127.0.0.1": true }
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

    // 两次独立的客户端连接，各发一个请求（走 HTTP 代理端口）
    let http_port = https_port - 1;
    for i in 0..2 {
        if i > 0 {
            // 留出时间让上一个连接归还到池
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let mut stream = TcpStream::connect(("127.0.0.1", http_port))
            .await
            .expect("连接代理失败");
        stream
            .write_all(
                format!(
                    "GET http://origin.test:{}/r{} HTTP/1.1\r\nHost: origin.test:{}\r\nConnection: close\r\n\r\n",
                    origin_port, i, origin_port
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.ends_with(b"ok") {
                        break;
                    }
                }
                _ => panic!("读取第 {} 个响应超时", i + 1),
            }
        }
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "第 {} 个请求期望 200 响应: {}",
            i + 1,
            text
        );
    }

    assert_eq!(
        conn_count.load(Ordering::SeqCst),
        1,
        "两次请求应复用同一条上游连接，实际建立了 {} 条",
        conn_count.load(Ordering::SeqCst)
    );
}

/// 大请求体（超过 streamBodyThreshold）走流式直通：源站应完整收到 body
#[tokio::test]
async fn proxy_streams_large_request_body() {
    let origin_port = 18084u16;
    let https_port = 34189u16;
    const BODY_LEN: usize = 8192;

    let listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("源站端口绑定失败");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // 读请求头，取出 Content-Length
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
                let head_text = String::from_utf8_lossy(&head).to_string();
                let len: usize = head_text
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                // 读满 body
                let mut body = vec![0u8; len];
                if len > 0 && socket.read_exact(&mut body).await.is_err() {
                    return;
                }
                let resp_body = format!("len={}", body.len());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    let pre_set_ip_list: serde_json::Value = serde_json::json!({
        "origin.test": { "127.0.0.1": true }
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
        // 阈值调低，使 8KB body 走流式路径
        setting: serde_json::json!({ "defaultTimeout": 10000, "streamBodyThreshold": 1024 }),
        intercepts: Arc::new(domain_map_regexply(None)),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    });

    let _server = ProxyServer::start(opts).await.expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", https_port - 1))
        .await
        .expect("连接代理失败");
    let payload = vec![b'x'; BODY_LEN];
    let mut req = format!(
        "POST http://origin.test:{}/upload HTTP/1.1\r\nHost: origin.test:{}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        origin_port, origin_port, BODY_LEN
    )
    .into_bytes();
    req.extend_from_slice(&payload);
    stream.write_all(&req).await.unwrap();

    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if out.ends_with(format!("len={}", BODY_LEN).as_bytes()) {
                    break;
                }
            }
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.starts_with("HTTP/1.1 200"), "期望 200 响应: {}", text);
    assert!(
        text.ends_with(&format!("len={}", BODY_LEN)),
        "源站应完整收到 {} 字节 body，实际响应: {}",
        BODY_LEN,
        text
    );
}

/// 502 之后同一 keep-alive 连接仍能正确处理后续请求
/// （验证失败路径不会因残留字节污染连接状态）
#[tokio::test]
async fn proxy_keeps_alive_after_502() {
    let origin_port = 18086u16;
    let https_port = 34195u16;

    // 源站：每个连接处理一个请求后关闭
    let listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("源站端口绑定失败");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
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
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    // 构造一个确定不可达的端口（绑定后立即释放）
    let dead_port = {
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let pre_set_ip_list: serde_json::Value = serde_json::json!({
        "good.test": { "127.0.0.1": true },
        "bad.test": { "127.0.0.1": true }
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
        setting: serde_json::json!({ "defaultTimeout": 5000 }),
        intercepts: Arc::new(domain_map_regexply(None)),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    });

    let _server = ProxyServer::start(opts).await.expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", https_port - 1))
        .await
        .expect("连接代理失败");

    // 1) 首个请求指向不可达上游 → 期望 502
    stream
        .write_all(
            format!(
                "GET http://bad.test:{}/x HTTP/1.1\r\nHost: bad.test:{}\r\n\r\n",
                dead_port, dead_port
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut byte)).await
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
    let head_text = String::from_utf8_lossy(&head).to_string();
    assert!(
        head_text.starts_with("HTTP/1.1 502"),
        "上游不可达应返回 502: {}",
        head_text
    );

    // 2) 同一连接继续发正常请求 → 期望 200（连接未被污染）
    stream
        .write_all(
            format!(
                "GET http://good.test:{}/y HTTP/1.1\r\nHost: good.test:{}\r\nConnection: close\r\n\r\n",
                origin_port, origin_port
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if out.ends_with(b"ok") {
                    break;
                }
            }
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "502 之后同一连接应能正常处理后续请求: {}",
        text
    );
}

/// 拦截模式测试：interceptMode = "intercepts-only" 时，无拦截规则的域名
/// 不做 MITM，CONNECT 走直连隧道。判别方式：客户端信任「源站自签证书」——
/// 直连隧道下握手成功；若被 MITM（证书由 DevSidecar CA 签发）则握手失败。
/// 全程不触碰 DEV_SIDECAR_HOME，避免与其他测试并行竞争
#[tokio::test]
async fn intercept_mode_intercepts_only_skips_mitm() {
    let origin_port = 18446u16;
    let https_port = 34193u16;

    // 自建 TLS 源站（自签证书）
    let kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost.test".to_string()]).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        "localhost.test".try_into().unwrap(),
    )];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    let origin_cert = params.self_signed(&kp).unwrap();
    let origin_cert_der = origin_cert.der().clone();
    let origin_key_der = rustls::pki_types::PrivateKeyDer::try_from(kp.serialize_der()).unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![origin_cert_der.clone()], origin_key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let origin_listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("源站端口绑定失败");
    {
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = origin_listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let resp =
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.flush().await;
                });
            }
        });
    }

    // intercepts 为空：intercepts-only 模式下该域名不会被解密
    let pre_set_ip_list: serde_json::Value = serde_json::json!({
        "localhost.test": { "127.0.0.1": true }
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
        setting: serde_json::json!({
            "defaultTimeout": 10000,
            "interceptMode": "intercepts-only"
        }),
        intercepts: Arc::new(domain_map_regexply(None)),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    });

    let _server = ProxyServer::start(opts).await.expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", https_port))
        .await
        .expect("连接代理失败");
    let connect = format!(
        "CONNECT localhost.test:{} HTTP/1.1\r\nHost: localhost.test:{}\r\n\r\n",
        origin_port, origin_port
    );
    stream.write_all(connect.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut buf = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        head.push(buf[0]);
    }
    assert!(
        String::from_utf8_lossy(&head).contains("200"),
        "CONNECT 未建立: {}",
        String::from_utf8_lossy(&head)
    );

    // 客户端仅信任「源站自签证书」：直连隧道 → 握手成功；被 MITM → 失败
    let mut roots = rustls::RootCertStore::empty();
    roots.add(origin_cert_der.clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let name = rustls::pki_types::ServerName::try_from("localhost.test")
        .unwrap()
        .to_owned();
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connector.connect(name, stream),
    )
    .await
    .expect("TLS 握手超时（intercepts-only 应走直连隧道）")
    .expect("TLS 握手失败：intercepts-only 模式下域名不应被 MITM 解密");

    // 直连下请求应直达源站
    tls.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if out.ends_with(b"ok") {
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"),
        "直连隧道应正常回源: {}",
        String::from_utf8_lossy(&out)
    );
}
