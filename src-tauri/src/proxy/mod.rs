//! MITM 代理服务核心（对应原版 mitmproxy 的 createServer / createRequestHandler / createConnectHandler）
//!
//! 本模块负责服务生命周期、连接监听与 CONNECT 处理（直连隧道 / MITM 解密）；
//! 单个请求的转发管线见 [`forward`]，上游建连见 [`connector`]。

pub mod connector;
pub mod forward;
pub mod http;
pub mod interceptor;

use crate::dns::{get_dns_and_family, is_ip, DnsConfig};
use crate::matcher::{match_hostname, DomainMap};
use crate::proxy::connector::{connect_any, UpstreamTarget};
use crate::proxy::http::{read_request_head, split_host_port, RequestHead};
use crate::speed::SpeedTester;
use crate::tls::CertificateAuthority;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

// ------------------------------------------------------------------ 流抽象

/// MITM 场景下由读写半流重组而来的 TLS 流
pub type ClientDuplex =
    Duplex<tokio::io::ReadHalf<ClientStream>, tokio::io::WriteHalf<ClientStream>>;

pub enum ClientStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    TlsDuplex(Box<TlsStream<ClientDuplex>>),
}

impl AsyncRead for ClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ClientStream::TlsDuplex(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ClientStream::TlsDuplex(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
            ClientStream::TlsDuplex(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ClientStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ClientStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ClientStream::TlsDuplex(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 把分离的读写半流重新组合成一个 AsyncRead + AsyncWrite（用于 MITM 握手）
pub struct Duplex<R, W> {
    pub r: R,
    pub w: W,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for Duplex<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.r).poll_read(cx, buf)
    }
}
impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for Duplex<R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.w).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

// ------------------------------------------------------------------ 服务配置

pub struct ServerOptions {
    pub host: String,
    pub port: u16,
    pub dns_config: DnsConfig,
    pub setting: Value,
    pub intercepts: Arc<DomainMap>,
    pub white_list: Arc<DomainMap>,
    pub sni_list: Arc<DomainMap>,
    pub speed: Option<Arc<SpeedTester>>,
    pub fake_server_max_length: usize,
}

pub struct ProxyServer {
    /// 广播停止信号；watch 会保留最新值，即使监听任务在信号发出后才轮询也不会漏掉。
    shutdown: watch::Sender<bool>,
    /// 监听任务句柄。`stop` 必须等它们退出并释放端口后才能返回，
    /// 否则前端立即重启会撞上尚未释放的监听端口。
    handles: AsyncMutex<Vec<JoinHandle<()>>>,
    pub http_port: u16,
    pub https_port: u16,
}

impl ProxyServer {
    pub async fn start(opts: Arc<ServerOptions>) -> Result<Self> {
        let https_port = opts.port;
        let http_port = if https_port > 0 { https_port - 1 } else { 0 };

        let https_listener = TcpListener::bind((opts.host.as_str(), https_port)).await?;
        let http_listener = TcpListener::bind((opts.host.as_str(), http_port)).await?;
        log_info!(
            "代理服务已启动: http://{}:{}   https://{}:{}",
            opts.host,
            http_port,
            opts.host,
            https_port
        );

        let (shutdown, _) = watch::channel(false);
        let http_task = spawn_listener(http_listener, opts.clone(), false, shutdown.subscribe());
        let https_task = spawn_listener(https_listener, opts.clone(), true, shutdown.subscribe());

        Ok(ProxyServer {
            shutdown,
            handles: AsyncMutex::new(vec![http_task, https_task]),
            http_port,
            https_port,
        })
    }

    /// 停止监听并等待两个端口真正释放，可安全地立即再次 `start`。
    pub async fn stop(&self) {
        let _ = self.shutdown.send(true);
        let handles = std::mem::take(&mut *self.handles.lock().await);
        for handle in handles {
            let _ = handle.await;
        }
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        // 兜底：未显式 stop 时也唤醒监听任务，避免任务永久占用端口。
        let _ = self.shutdown.send(true);
    }
}

fn spawn_listener(
    listener: TcpListener,
    opts: Arc<ServerOptions>,
    is_https: bool,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => match accepted {
                    Ok((socket, addr)) => {
                        let opts = opts.clone();
                        let conn_id = crate::util::diag::next_id("conn");
                        tokio::spawn(async move {
                            if let Err(e) =
                                serve_connection(ClientStream::Plain(socket), opts, is_https, &conn_id)
                                    .await
                            {
                                log_debug!(
                                    "diag conn={} event=end addr={} reason={}",
                                    conn_id,
                                    addr,
                                    e
                                );
                            }
                        });
                    }
                    Err(e) => {
                        log_error!("accept 失败: {}", e);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                },
            }
        }
        drop(listener);
    })
}

async fn serve_connection(
    stream: ClientStream,
    opts: Arc<ServerOptions>,
    is_https_port: bool,
    conn_id: &str,
) -> Result<()> {
    let (rh, mut wh) = tokio::io::split(stream);
    // 整个连接生命周期共用一个 BufReader，避免重建时丢失已缓冲的请求体/流水线请求
    let mut reader = BufReader::new(rh);
    loop {
        let Some(head) = read_request_head(&mut reader).await? else {
            return Ok(());
        };

        if head.method == "CONNECT" {
            let rh = reader.into_inner();
            return handle_connect(rh, wh, opts, head, conn_id).await;
        }

        let keep_alive =
            forward::handle_request(&mut reader, &mut wh, &opts, head, is_https_port, conn_id)
                .await?;
        wh.flush().await?;
        if !keep_alive {
            return Ok(());
        }
    }
}

// ------------------------------------------------------------------ CONNECT

async fn handle_connect(
    mut rh: tokio::io::ReadHalf<ClientStream>,
    mut wh: tokio::io::WriteHalf<ClientStream>,
    opts: Arc<ServerOptions>,
    head: RequestHead,
    conn_id: &str,
) -> Result<()> {
    let (host, port) = split_host_port(&head.target);
    let port = port.unwrap_or(443);

    let is_ip_target = is_ip(&host);
    // 匹配结果需同时检查条目值：值为 false 时视为未启用（与原版语义一致）
    let matched_enabled = |v: Option<&Value>| !matches!(v, Some(Value::Bool(false)) | None);
    let in_white_list = matched_enabled(match_hostname(&opts.white_list, &host, "white list"));
    let has_intercept = matched_enabled(match_hostname(&opts.intercepts, &host, "intercepts"));
    // 拦截模式（server.setting.interceptMode）：
    // - "intercepts-only"（默认）：仅解密拦截规则命中的域名（保守模式，普通网站直接隧道透传，
    //   不依赖本地根证书，避免证书未安装时其他网站全部无法访问）
    // - "all-but-whitelist"：非白名单域名均解密（与原版行为一致，需确保根证书已安装）
    let intercept_mode = opts
        .setting
        .get("interceptMode")
        .and_then(|v| v.as_str())
        .unwrap_or("intercepts-only");
    let do_intercept = !is_ip_target
        && if intercept_mode == "intercepts-only" {
            has_intercept
        } else {
            has_intercept || !in_white_list
        };

    log_info!(
        "diag conn={} route={} target={}:{} mode={} intercept_rule={} whitelist={}",
        conn_id,
        if do_intercept { "mitm" } else { "tunnel" },
        host,
        port,
        intercept_mode,
        has_intercept,
        in_white_list
    );

    if !do_intercept {
        let dns_started = Instant::now();
        let ip = resolve_target_ip(&opts, &host, is_ip_target).await;
        let dns_ms = crate::util::diag::elapsed_ms(dns_started);
        let started = Instant::now();
        let upstream = match connect_tunnel(&ip, port, &host).await {
            Ok(s) => s,
            Err(e) => {
                // 回 502 让客户端能感知到具体错误，而非连接被无声关闭
                log_error!("直连隧道建立失败 {}: {}", host, e);
                let body = format!("DS-Connect-Error: {}\n", e);
                let resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = wh.write_all(resp.as_bytes()).await;
                let _ = wh.flush().await;
                return Ok(());
            }
        };
        wh.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        wh.flush().await?;
        let (mut ur, mut uw) = tokio::io::split(upstream);
        let c1 = tokio::io::copy(&mut rh, &mut uw);
        let c2 = tokio::io::copy(&mut ur, &mut wh);
        let (r1, r2) = tokio::join!(c1, c2);
        log_info!(
            "diag conn={} route=tunnel target={}:{} event=finish status=200 dns_ms={} tunnel_ms={} client_bytes={} upstream_bytes={} end={}",
            conn_id,
            host,
            port,
            dns_ms,
            crate::util::diag::elapsed_ms(started),
            r1.map(|n| n.to_string()).unwrap_or_else(|e| format!("err:{}", e.kind())),
            r2.map(|n| n.to_string()).unwrap_or_else(|e| format!("err:{}", e.kind())),
            "closed"
        );
        return Ok(());
    }

    // MITM：伪造证书，解密后按普通请求处理
    let ca = current_ca()?;
    let config = ca.get_server_config(&host)?;
    let acceptor = TlsAcceptor::from(config);

    // 先回应隧道建立成功，再进行 TLS 握手
    let mut duplex = Duplex { r: rh, w: wh };
    duplex
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    duplex.flush().await?;
    let tls_started = Instant::now();
    let tls_stream = match acceptor.accept(duplex).await {
        Ok(s) => s,
        Err(e) => {
            log_warn!(
                "diag conn={} route=mitm target={}:{} event=tls_failed tls_ms={} reason={}",
                conn_id,
                host,
                port,
                crate::util::diag::elapsed_ms(tls_started),
                e
            );
            return Ok(());
        }
    };
    log_info!(
        "diag conn={} route=mitm target={}:{} event=client_tls_ready tls_ms={}",
        conn_id,
        host,
        port,
        crate::util::diag::elapsed_ms(tls_started)
    );

    let (tls_rh, mut tls_wh) = tokio::io::split(ClientStream::TlsDuplex(Box::new(tls_stream)));
    let mut tls_reader = BufReader::new(tls_rh);
    loop {
        let Some(head) = read_request_head(&mut tls_reader).await? else {
            return Ok(());
        };
        let keep_alive =
            forward::handle_request(&mut tls_reader, &mut tls_wh, &opts, head, true, conn_id)
                .await?;
        tls_wh.flush().await?;
        if !keep_alive {
            return Ok(());
        }
    }
}

fn current_ca() -> Result<Arc<CertificateAuthority>> {
    crate::app::ensure_ca()
}

/// 直连隧道建连：与拦截路径一致走 `connect_any`（Happy Eyeballs 多地址错峰尝试），
/// 避免「首个地址不可达即整体失败」
async fn connect_tunnel(ip: &str, port: u16, host: &str) -> Result<TcpStream> {
    let target = UpstreamTarget {
        https: false,
        host: host.to_string(),
        ip: ip.to_string(),
        port,
        sni: None,
        verify: false,
        allow_tls12: false,
        allow_http2: false,
    };
    connect_any(&target)
        .await
        .map_err(|e| anyhow!("TCP 连接失败 {}: {}", host, e))
}

async fn resolve_target_ip(opts: &ServerOptions, hostname: &str, is_ip_target: bool) -> String {
    if is_ip_target {
        return hostname.to_string();
    }
    if let Some(speed) = &opts.speed {
        if let Some(ip) = speed.best_ip(hostname) {
            return ip;
        }
    }
    if let Some((dns, family)) = get_dns_and_family(&opts.dns_config, hostname) {
        // DoH/DoT 上游可能被阻断导致长时间阻塞，限时后回退系统解析（connect_any 会按域名走系统 DNS）
        if let Ok(Some(ip)) =
            tokio::time::timeout(Duration::from_secs(3), dns.lookup(hostname, family, None)).await
        {
            if is_ip(&ip) {
                return ip;
            }
        }
    }
    hostname.to_string()
}
