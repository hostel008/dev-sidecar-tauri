//! 自定义 upstream 连接器：支持指定 IP、SNI 改写、跳过证书校验

use crate::tls::cached_client_config;
use ::http::Uri;
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use once_cell::sync::Lazy;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub use hyper_util::rt::TokioIo;

#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    pub https: bool,
    /// 原始主机名（用于 Host 头与证书校验）
    pub host: String,
    /// 实际连接地址（IP 或主机名）
    pub ip: String,
    pub port: u16,
    pub sni: Option<String>,
    pub verify: bool,
    pub allow_tls12: bool,
    /// 是否允许与上游协商 HTTP/2（ALPN 声明 h2）
    pub allow_http2: bool,
}

pub enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Conn {
    /// 是否已通过 ALPN 与上游协商出 h2
    fn is_h2(&self) -> bool {
        match self {
            Conn::Plain(_) => false,
            Conn::Tls(s) => s.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()),
        }
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 实现 hyper 所需的 Connection 约束
pub struct ProxyConn(pub Conn);

impl hyper::rt::Read for ProxyConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::pin::Pin;
        use tokio::io::AsyncRead;
        let this = self.get_mut();
        unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            let before = tbuf.filled().len();
            match Pin::new(&mut this.0).poll_read(cx, &mut tbuf) {
                std::task::Poll::Ready(Ok(())) => {
                    let n = tbuf.filled().len() - before;
                    buf.advance(n);
                    std::task::Poll::Ready(Ok(()))
                }
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }
}

impl hyper::rt::Write for ProxyConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use tokio::io::AsyncWrite;
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use tokio::io::AsyncWrite;
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use tokio::io::AsyncWrite;
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for ProxyConn {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let mut connected = hyper_util::client::legacy::connect::Connected::new();
        // 告知 hyper 该连接已通过 ALPN 协商出 h2，否则会以 HTTP/1.1 编解码
        // 发送请求而与上游 h2 服务端不匹配
        if self.0.is_h2() {
            connected = connected.negotiated_h2();
        }
        connected
    }
}

#[derive(Clone)]
pub struct DsConnector {
    target: Arc<UpstreamTarget>,
    config: Arc<rustls::ClientConfig>,
}

impl DsConnector {
    pub fn new(target: UpstreamTarget) -> anyhow::Result<Self> {
        let config = cached_client_config(target.verify, target.allow_tls12, target.allow_http2)?;
        Ok(DsConnector {
            target: Arc::new(target),
            config,
        })
    }
}

impl tower_service::Service<Uri> for DsConnector {
    type Response = ProxyConn;
    type Error = std::io::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let target = self.target.clone();
        let config = self.config.clone();
        Box::pin(async move {
            let tcp = connect_any(&target).await.map_err(|e| {
                std::io::Error::new(e.kind(), format!("TCP 连接失败 {}: {}", target.host, e))
            })?;
            tcp.set_nodelay(true).ok();
            if !target.https {
                return Ok(ProxyConn(Conn::Plain(tcp)));
            }
            let server_name_str = match target.sni.as_deref() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => target.host.clone(),
            };
            let name = rustls::pki_types::ServerName::try_from(server_name_str.clone())
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "非法 servername")
                })?
                .to_owned();
            let connector = tokio_rustls::TlsConnector::from(config);
            let stream = connector.connect(name, tcp).await.map_err(|e| {
                std::io::Error::other(format!("TLS 握手失败 {}: {}", server_name_str, e))
            })?;
            Ok(ProxyConn(Conn::Tls(Box::new(stream))))
        })
    }
}

/// IPv4 优先排序（组内保持解析顺序）：国内网络 IPv6 常不可达，优先尝试 A 记录
fn order_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (mut v4, mut v6): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.into_iter().partition(SocketAddr::is_ipv4);
    v4.append(&mut v6);
    v4
}

/// 解析上游地址：IPv4 优先（与配置中 dns family 默认 4 的取向一致），IPv6 保留作为回退
async fn resolve_addrs(target: &UpstreamTarget) -> std::io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = target.ip.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((target.ip.as_str(), target.port))
        .await?
        .collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "无法解析主机",
        ));
    }
    Ok(order_addrs(addrs))
}

/// 建连：多地址错峰并发尝试（对齐 Node 的 autoSelectFamily / Happy Eyeballs），
/// 先连上者胜出；全部失败时返回最后一次错误，避免“首个地址不可达即整体失败”。
/// 直连隧道（CONNECT 不解密分支）也复用本函数
pub async fn connect_any(target: &UpstreamTarget) -> std::io::Result<TcpStream> {
    /// 相邻地址的启动间隔（Node autoSelectFamilyAttemptTimeout 默认值）
    const STAGGER_MS: u64 = 250;

    let addrs = resolve_addrs(target).await.map_err(|e| {
        std::io::Error::new(e.kind(), format!("DNS 解析失败 {}: {}", target.host, e))
    })?;

    let mut connecting = FuturesUnordered::new();
    for (i, addr) in addrs.into_iter().enumerate() {
        let delay = Duration::from_millis(STAGGER_MS * i as u64);
        connecting.push(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            TcpStream::connect(addr)
                .await
                .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {}", addr, e)))
        });
    }

    let mut last_err = None;
    while let Some(res) = connecting.next().await {
        match res {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err
        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "无可连接地址")))
}

// ------------------------------------------------------------------ 客户端池

/// 池化 key：连接按「实际 IP + 端口 + SNI + 校验策略 + TLS 版本 + 协议」路由，
/// 任一维度变化都必须使用不同客户端，否则会复用到错误目标
/// （例如测速切换优选 IP 后，旧 key 的连接不会被新请求命中）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamKey {
    pub https: bool,
    /// 原始主机名（Host 头 / 证书校验）
    pub host: String,
    /// 实际连接地址（优选 IP 或域名）
    pub ip: String,
    pub port: u16,
    pub sni: Option<String>,
    pub verify: bool,
    pub allow_tls12: bool,
    pub allow_http2: bool,
}

impl UpstreamKey {
    pub fn from_target(target: &UpstreamTarget) -> Self {
        Self {
            https: target.https,
            host: target.host.clone(),
            ip: target.ip.clone(),
            port: target.port,
            sni: target.sni.clone(),
            verify: target.verify,
            allow_tls12: target.allow_tls12,
            allow_http2: target.allow_http2,
        }
    }

    fn to_target(&self) -> UpstreamTarget {
        UpstreamTarget {
            https: self.https,
            host: self.host.clone(),
            ip: self.ip.clone(),
            port: self.port,
            sni: self.sni.clone(),
            verify: self.verify,
            allow_tls12: self.allow_tls12,
            allow_http2: self.allow_http2,
        }
    }

    fn describe(&self) -> String {
        format!(
            "{}://{} ({}:{}, sni={:?}, verify={}, tls12={}, h2={})",
            if self.https { "https" } else { "http" },
            self.host,
            self.ip,
            self.port,
            self.sni,
            self.verify,
            self.allow_tls12,
            self.allow_http2
        )
    }
}

/// 上游客户端类型（hyper Client 自带连接池）
pub type PooledClient = hyper_util::client::legacy::Client<DsConnector, Full<Bytes>>;

/// duplex 管道桥接的流式 body（ReaderStream 映射为 http_body Frame）
type DuplexFrameStream = futures_util::stream::Map<
    tokio_util::io::ReaderStream<tokio::io::DuplexStream>,
    fn(Result<Bytes, std::io::Error>) -> Result<http_body::Frame<Bytes>, std::io::Error>,
>;

/// 流式请求体客户端：body 为 duplex 管道桥接的流（大文件上传直通转发）
pub type StreamClient =
    hyper_util::client::legacy::Client<DsConnector, http_body_util::StreamBody<DuplexFrameStream>>;

/// 空闲连接保留时长；超过后 hyper 自动关闭池内空闲连接
pub const POOL_IDLE_TIMEOUT_SECS: u64 = 90;
/// 同一 host 的最大空闲连接数
pub const POOL_MAX_IDLE_PER_HOST: usize = 8;
/// 池内最大客户端数（按 UpstreamKey 计，LRU 淘汰）
const POOL_MAX_CLIENTS: usize = 128;

/// 上游客户端池：按 UpstreamKey 复用 hyper Client（每个 Client 内部自带连接池），
/// 避免每请求新建 TCP + TLS 握手。Client 由 Arc 共享，被 LRU 淘汰后仍存活到
/// 所有在途响应结束
pub struct ClientPool {
    clients: parking_lot::Mutex<lru::LruCache<UpstreamKey, Arc<PooledClient>>>,
    stream_clients: parking_lot::Mutex<lru::LruCache<UpstreamKey, Arc<StreamClient>>>,
}

impl ClientPool {
    fn new() -> Self {
        ClientPool {
            clients: parking_lot::Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(POOL_MAX_CLIENTS).unwrap(),
            )),
            stream_clients: parking_lot::Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(POOL_MAX_CLIENTS).unwrap(),
            )),
        }
    }

    /// 取（或构建并缓存）池化客户端
    pub fn get_or_build(&self, key: UpstreamKey) -> anyhow::Result<Arc<PooledClient>> {
        if let Some(c) = self.clients.lock().get(&key) {
            log_debug!("连接池命中: {}", key.describe());
            return Ok(c.clone());
        }
        let client = Arc::new(Self::build(key.to_target())?);
        self.clients.lock().put(key, client.clone());
        Ok(client)
    }

    /// 取（或构建并缓存）流式请求体客户端（与缓冲客户端按 body 类型分池）
    pub fn get_or_build_streaming(&self, key: UpstreamKey) -> anyhow::Result<Arc<StreamClient>> {
        if let Some(c) = self.stream_clients.lock().get(&key) {
            log_debug!("流式连接池命中: {}", key.describe());
            return Ok(c.clone());
        }
        let connector = DsConnector::new(key.to_target())?;
        let client = Arc::new(
            Client::builder(TokioExecutor::new())
                .pool_idle_timeout(Some(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS)))
                .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
                .build(connector),
        );
        self.stream_clients.lock().put(key, client.clone());
        Ok(client)
    }

    /// 构建池化客户端：启用连接复用
    fn build(target: UpstreamTarget) -> anyhow::Result<PooledClient> {
        let connector = DsConnector::new(target)?;
        Ok(Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Some(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS)))
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
            .build(connector))
    }

    /// 构建一次性客户端（不复用连接）：用于 WebSocket / 协议升级等
    /// 连接不能归还池的场景
    pub fn build_oneshot(target: UpstreamTarget) -> anyhow::Result<PooledClient> {
        let connector = DsConnector::new(target)?;
        Ok(Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(0)
            .build(connector))
    }
}

static CLIENT_POOL: Lazy<ClientPool> = Lazy::new(ClientPool::new);

/// 进程级上游客户端池
pub fn client_pool() -> &'static ClientPool {
    &CLIENT_POOL
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 多地址一律 IPv4 优先，且每组内保持解析顺序（回退只在连接失败时发生）
    #[test]
    fn order_addrs_puts_ipv4_first() -> Result<(), Box<dyn std::error::Error>> {
        let v6a = "[2001:db8::1]:443".parse::<SocketAddr>()?;
        let v6b = "[2001:db8::2]:443".parse::<SocketAddr>()?;
        let v4a = "1.2.3.4:443".parse::<SocketAddr>()?;
        let v4b = "5.6.7.8:443".parse::<SocketAddr>()?;

        assert_eq!(
            order_addrs(vec![v6a, v4a, v6b, v4b]),
            vec![v4a, v4b, v6a, v6b]
        );
        assert_eq!(order_addrs(vec![v4a]), vec![v4a]);
        assert_eq!(order_addrs(vec![v6a]), vec![v6a]);
        Ok(())
    }
}
