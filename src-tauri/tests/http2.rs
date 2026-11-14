//! HTTP/2 上游测试：代理与上游协商 h2（ALPN），源站应收到 HTTP/2 请求；
//! 对客户端侧仍以 HTTP/1.1 回写

use bytes::Bytes;
use dev_sidecar_tauri_lib::dns::{init_dns, DnsConfig};
use dev_sidecar_tauri_lib::matcher::domain_map_regexply;
use dev_sidecar_tauri_lib::proxy::{ProxyServer, ServerOptions};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

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

/// 启动 ALPN 支持 h2 的源站，把请求的 HTTP 版本号放入响应体
async fn start_h2_origin(listener: TcpListener) {
    let (cert, key) = origin_cert();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(socket).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    // 模拟严格 CDN 行为（RFC 9113 §8.3.1 允许拒绝）：
                    // 1) h2 请求不应携带 host 头（合规客户端只发 :authority 伪头），
                    //    转发 host（即使值一致）会被部分网关返回 400
                    // 2) :authority 必须非空（npmmirror 等真实场景的回归校验）
                    let authority = req
                        .uri()
                        .authority()
                        .map(|a| a.to_string())
                        .unwrap_or_default();
                    if req.headers().contains_key(::http::header::HOST) {
                        return Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(400)
                                .body(Full::new(Bytes::from(format!(
                                    "unexpected host header, authority({})",
                                    authority
                                ))))
                                .unwrap(),
                        );
                    }
                    if authority.is_empty() {
                        return Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(400)
                                .body(Full::new(Bytes::from("missing authority")))
                                .unwrap(),
                        );
                    }
                    let version = format!("{:?}", req.version());
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                        version,
                    ))))
                });
                // 强制 h2：若客户端没有真正按 h2 发送请求，这里会失败
                // （比 auto 协商更能确证代理走了 HTTP/2 上游）
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
}

#[tokio::test]
async fn proxy_negotiates_http2_upstream() {
    let temp = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("ds-h2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    std::env::set_var("DEV_SIDECAR_HOME", &temp);

    let origin_port = 18445u16;
    let https_port = 34191u16;

    let origin_listener = TcpListener::bind(("127.0.0.1", origin_port))
        .await
        .expect("源站端口绑定失败");
    start_h2_origin(origin_listener).await;
    dev_sidecar_tauri_lib::app::ensure_ca().expect("初始化 CA 失败");

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
        setting: serde_json::json!({ "defaultTimeout": 10000, "allowHttp2": true }),
        intercepts: Arc::new(domain_map_regexply(Some(&intercepts))),
        white_list: Arc::new(domain_map_regexply(None)),
        sni_list: Arc::new(domain_map_regexply(None)),
        speed: None,
        fake_server_max_length: 10,
    });

    let _server = ProxyServer::start(opts).await.expect("启动代理失败");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // CONNECT 隧道
    let mut stream = TcpStream::connect(("127.0.0.1", https_port))
        .await
        .expect("连接代理失败");
    let connect = format!(
        "CONNECT localhost.test:{} HTTP/1.1\r\nHost: localhost.test:{}\r\n\r\n",
        origin_port, origin_port
    );
    stream.write_all(connect.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await.unwrap();
        if n == 0 {
            break;
        }
        head.push(byte[0]);
    }
    assert!(
        String::from_utf8_lossy(&head).contains("200"),
        "CONNECT 未建立: {}",
        String::from_utf8_lossy(&head)
    );

    // 用本地 CA 完成 MITM 握手（客户端侧不声明 ALPN，按 HTTP/1.1 收发）
    let ca_pem = std::fs::read(dev_sidecar_tauri_lib::util::paths::ca_cert_path()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let name = rustls::pki_types::ServerName::try_from("localhost.test")
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(name, stream).await.expect("TLS 握手失败");

    tls.write_all(
        format!(
            "GET /version HTTP/1.1\r\nHost: localhost.test:{}\r\nConnection: close\r\n\r\n",
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
                if String::from_utf8_lossy(&out).ends_with("HTTP/2.0") {
                    break;
                }
            }
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    println!("响应:\n{}", text);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "客户端侧应保持 HTTP/1.1 响应: {}",
        text
    );
    assert!(
        text.ends_with("HTTP/2.0"),
        "上游应协商出 HTTP/2（源站报告版本），实际响应: {}",
        text
    );

    let _ = std::fs::remove_dir_all(&temp);
}
