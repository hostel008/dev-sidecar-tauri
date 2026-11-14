//! 最小 HTTP/1.1 报文解析与写入工具（代理服务端使用）

use anyhow::Result;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    pub fn header_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (k, v) in &self.headers {
            map.insert(k.to_lowercase(), v.clone());
        }
        map
    }
}

/// 读取请求头（首行 + headers），连接关闭时返回 None
pub async fn read_request_head<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Option<RequestHead>> {
    // 跳过前置空行（部分客户端会在 keep-alive 后发送额外 CRLF）
    loop {
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = trim_crlf(&line);
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            anyhow::bail!("非法请求行: {}", trimmed);
        }
        let method = parts[0].to_string();
        let target = parts[1].to_string();
        let version = parts.get(2).unwrap_or(&"HTTP/1.1").to_string();

        let mut headers = Vec::new();
        loop {
            let mut h = Vec::new();
            let n = reader.read_until(b'\n', &mut h).await?;
            if n == 0 {
                break;
            }
            let text = trim_crlf(&h);
            if text.is_empty() {
                break;
            }
            if let Some(idx) = text.find(':') {
                let key = text[..idx].trim().to_string();
                let value = text[idx + 1..].trim().to_string();
                headers.push((key, value));
            }
        }
        return Ok(Some(RequestHead {
            method,
            target,
            version,
            headers,
        }));
    }
}

fn trim_crlf(buf: &[u8]) -> String {
    let end = buf.len();
    let mut start = 0;
    let mut stop = end;
    while stop > start && (buf[stop - 1] == b'\r' || buf[stop - 1] == b'\n') {
        stop -= 1;
    }
    while start < stop && (buf[start] == b'\r' || buf[start] == b'\n') {
        start += 1;
    }
    String::from_utf8_lossy(&buf[start..stop]).to_string()
}

/// 读取请求体（支持 Content-Length 与 chunked）
pub async fn read_request_body<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    head: &RequestHead,
    cap: usize,
) -> Result<Vec<u8>> {
    let te = head
        .header("transfer-encoding")
        .unwrap_or("")
        .to_lowercase();
    if te.contains("chunked") {
        return Ok(read_chunked(reader, cap).await?);
    }
    if let Some(len) = head.header("content-length") {
        let len: usize = len.trim().parse().unwrap_or(0);
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > cap {
            anyhow::bail!("请求体过大: {}", len);
        }
        let mut buf = vec![0u8; len];
        use tokio::io::AsyncReadExt;
        reader.read_exact(&mut buf).await?;
        return Ok(buf);
    }
    Ok(Vec::new())
}

async fn read_chunked<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    cap: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            break;
        }
        let text = trim_crlf(&line);
        let size_part = text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_part, 16).unwrap_or(0);
        if size == 0 {
            // 读取 trailer
            loop {
                let mut t = Vec::new();
                if reader.read_until(b'\n', &mut t).await? == 0 {
                    break;
                }
                if trim_crlf(&t).is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() + size > cap {
            anyhow::bail!("chunked 请求体过大");
        }
        let mut chunk = vec![0u8; size];
        use tokio::io::AsyncReadExt;
        reader.read_exact(&mut chunk).await?;
        out.extend_from_slice(&chunk);
        // 吃掉 chunk 后的 CRLF
        let mut crlf = [0u8; 2];
        let _ = tokio::io::AsyncReadExt::read_exact(reader, &mut crlf).await;
    }
    Ok(out)
}

pub fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

/// 响应头集合：保持顺序，同名覆盖
#[derive(Debug, Clone, Default)]
pub struct HeaderList {
    items: Vec<(String, String)>,
}

impl HeaderList {
    pub fn new() -> Self {
        HeaderList { items: Vec::new() }
    }
    pub fn set(&mut self, name: &str, value: &str) {
        let lower = name.to_lowercase();
        if let Some(pos) = self
            .items
            .iter()
            .position(|(k, _)| k.to_lowercase() == lower)
        {
            self.items[pos] = (name.to_string(), value.to_string());
        } else {
            self.items.push((name.to_string(), value.to_string()));
        }
    }
    /// 追加同名头（保留 Set-Cookie 等可重复头的多值）
    pub fn append(&mut self, name: &str, value: &str) {
        self.items.push((name.to_string(), value.to_string()));
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.items
            .iter()
            .rev()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
    pub fn remove(&mut self, name: &str) {
        let lower = name.to_lowercase();
        self.items.retain(|(k, _)| k.to_lowercase() != lower);
    }
    pub fn items(&self) -> &[(String, String)] {
        &self.items
    }
    pub fn iter(&self) -> std::slice::Iter<'_, (String, String)> {
        self.items.iter()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// 写入状态行与响应头
pub async fn write_response_head<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: u16,
    headers: &HeaderList,
) -> Result<()> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", status, status_reason(status));
    for (k, v) in headers.iter() {
        if v.is_empty() {
            continue;
        }
        out.push_str(&format!("{}: {}\r\n", k, v));
    }
    out.push_str("\r\n");
    w.write_all(out.as_bytes()).await?;
    Ok(())
}

/// 流式读取请求体并写入 `w`（支持 Content-Length 与 chunked）。
/// 用于超大请求体的直通转发：不缓冲在内存，边读边转发。
/// 调用方需保证 `w` 关闭/丢弃后连接语义正确（流式路径不复用客户端连接）。
pub async fn copy_request_body_to<R, W>(
    reader: &mut BufReader<R>,
    head: &RequestHead,
    w: &mut W,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let te = head
        .header("transfer-encoding")
        .unwrap_or("")
        .to_lowercase();
    if te.contains("chunked") {
        copy_chunked_to(reader, w).await
    } else if let Some(len) = head.header("content-length") {
        let len: u64 = len.trim().parse().unwrap_or(0);
        if len > 0 {
            copy_exact_to(reader, w, len).await?;
        }
        Ok(())
    } else {
        Ok(())
    }
}

/// 逐块（64KB）搬运指定长度的字节，避免整体读入内存
async fn copy_exact_to<R, W>(reader: &mut BufReader<R>, w: &mut W, mut len: u64) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 64 * 1024];
    while len > 0 {
        let want = buf.len().min(len as usize);
        let n = reader.read(&mut buf[..want]).await?;
        if n == 0 {
            anyhow::bail!("请求体意外结束（剩余 {} 字节）", len);
        }
        w.write_all(&buf[..n]).await?;
        len -= n as u64;
    }
    Ok(())
}

/// 流式解析 chunked 编码：逐 chunk 转发，结束后消费 trailer
async fn copy_chunked_to<R, W>(reader: &mut BufReader<R>, w: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).await?;
        let text = trim_crlf(&line);
        let size_part = text.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_part, 16).unwrap_or(0);
        w.write_all(&line).await?;
        if size == 0 {
            // 读取并转发 trailer
            loop {
                let mut t = Vec::new();
                if reader.read_until(b'\n', &mut t).await? == 0 {
                    break;
                }
                w.write_all(&t).await?;
                if trim_crlf(&t).is_empty() {
                    break;
                }
            }
            return Ok(());
        }
        copy_exact_to(reader, w, size).await?;
        // 消费并转发 chunk 后的 CRLF
        let mut crlf = [0u8; 2];
        use tokio::io::AsyncReadExt;
        let n = reader.read_exact(&mut crlf).await?;
        w.write_all(&crlf[..n]).await?;
        if n < 2 || &crlf != b"\r\n" {
            anyhow::bail!("chunked 编码格式错误");
        }
    }
}

/// 从请求 target 中解析出 (协议, 主机名, 端口, 路径)
pub fn parse_target(target: &str, default_ssl: bool) -> (String, String, u16, String) {
    if target.starts_with("http://") || target.starts_with("https://") {
        let rest = &target[target.find("://").unwrap() + 3..];
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = split_host_port(authority);
        let protocol = if target.starts_with("https:") {
            "https:"
        } else {
            "http:"
        };
        let port = port.unwrap_or(if protocol == "https:" { 443 } else { 80 });
        return (protocol.to_string(), host, port, path);
    }

    // 相对路径形式：从 Host 头取主机（由调用方处理），这里仅返回路径
    let _ = default_ssl;
    ("http:".to_string(), String::new(), 0, target.to_string())
}

pub fn split_host_port(authority: &str) -> (String, Option<u16>) {
    if authority.starts_with('[') {
        if let Some(idx) = authority.find(']') {
            let host = authority[1..idx].to_string();
            let rest = &authority[idx + 1..];
            if let Some(p) = rest.strip_prefix(':') {
                return (host, p.parse().ok());
            }
            return (host, None);
        }
    }
    match authority.rfind(':') {
        Some(idx) => {
            let (host, port) = (&authority[..idx], &authority[idx + 1..]);
            (host.to_string(), port.parse().ok())
        }
        None => (authority.to_string(), None),
    }
}
