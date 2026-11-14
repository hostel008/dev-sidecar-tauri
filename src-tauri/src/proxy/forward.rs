//! 请求转发管线（自 mod.rs 拆分）：
//! 请求拦截 → 读取请求体 → DNS/测速优选 → 上游请求（含重试）
//! → 响应拦截 → 脚本注入 / 流式回写

use crate::dns::{get_dns_and_family, is_ip};
use crate::event::traffic;
use crate::matcher::match_hostname;
use crate::proxy::connector::{
    client_pool, ClientPool, PooledClient, StreamClient, UpstreamKey, UpstreamTarget,
};
use crate::proxy::http::{
    copy_request_body_to, parse_target, read_request_body, split_host_port, status_reason,
    write_response_head, HeaderList, RequestHead,
};
use crate::proxy::interceptor::{
    create_intercepts, default_retry_methods, InterceptContext, InterceptOutcome, RequestOptions,
    UpstreamHeads,
};
use crate::proxy::ServerOptions;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::StreamExt as _;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_BUFFERED_BODY: usize = 20 * 1024 * 1024;
const MAX_INJECT_BODY: usize = 8 * 1024 * 1024;
/// 请求体超过该阈值（Content-Length 显式声明）时改走流式直通转发，
/// 可通过 `server.setting.streamBodyThreshold` 覆盖
const STREAM_BODY_THRESHOLD: u64 = 1024 * 1024;

// ------------------------------------------------------------------ 上游响应

/// 持有发起本次请求的客户端，保证响应消费完成前 Client 不被回收
/// （字段仅用于 RAII 保活，不主动读取）
#[allow(dead_code)]
enum ClientHolder {
    Buffered(Arc<PooledClient>),
    Streaming(Arc<StreamClient>),
}

/// 上游响应（保持 hyper client 存活以便流式读取；池化后连接归还由
/// Client 内部连接池管理，Client 由 Arc 持有到响应结束）
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Incoming>,
    /// 协议升级句柄（上游返回 101 时存在，用于接管上游连接）
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    client: Option<ClientHolder>,
}

// ------------------------------------------------------------------ 诊断

/// 单请求脱敏诊断。Drop 时输出一行完整摘要，确保所有返回路径（含 ? 提前返回）
/// 都有结束记录；不记录查询串、Cookie、Authorization、代理认证、正文。
struct RequestDiag {
    conn: String,
    id: String,
    route: &'static str,
    method: String,
    host: String,
    port: u16,
    path: String,
    start: std::time::Instant,
    dns_ms: Option<u128>,
    upstream_ms: Option<u128>,
    status: Option<u16>,
    retries: u32,
    end: &'static str,
    error: Option<String>,
}

impl RequestDiag {
    fn fail(&mut self, status: u16, reason: String, end: &'static str) {
        self.status = Some(status);
        self.error = Some(crate::util::diag::safe_text(&reason));
        self.end = end;
    }
}

impl Drop for RequestDiag {
    fn drop(&mut self) {
        log_info!(
            "diag conn={} req={} event=finish route={} method={} target={}:{}{} status={} retries={} dns_ms={} upstream_ms={} total_ms={} end={} error={}",
            self.conn,
            self.id,
            self.route,
            self.method,
            self.host,
            self.port,
            self.path,
            self.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            self.retries,
            self.dns_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            self.upstream_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            crate::util::diag::elapsed_ms(self.start),
            self.end,
            self.error.as_deref().unwrap_or("-")
        );
    }
}

// ------------------------------------------------------------------ 主入口

/// 处理单个（已解密或明文的）HTTP 请求，返回是否保持连接
pub async fn handle_request<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    opts: &Arc<ServerOptions>,
    head: RequestHead,
    ssl: bool,
    conn_id: &str,
) -> Result<bool> {
    let (protocol, hostname, port, path) = resolve_target(&head, ssl);
    let mut diag = RequestDiag {
        conn: conn_id.to_string(),
        id: crate::util::diag::next_id("req"),
        route: if ssl { "mitm-http" } else { "proxy-http" },
        method: head.method.clone(),
        host: hostname.clone(),
        port,
        path: crate::util::diag::safe_path(&path),
        start: std::time::Instant::now(),
        dns_ms: None,
        upstream_ms: None,
        status: None,
        retries: 0,
        end: "closed",
        error: None,
    };
    if hostname.is_empty() {
        diag.fail(400, "invalid target".into(), "invalid_target");
        let mut headers = HeaderList::new();
        headers.set("Content-Type", "text/plain; charset=utf-8");
        headers.set("Content-Length", "0");
        write_response_head(writer, 400, &headers).await?;
        return Ok(false);
    }

    let mut r_options = RequestOptions {
        protocol,
        method: head.method.clone(),
        hostname: hostname.clone(),
        port,
        path: path.clone(),
        headers: head.headers.clone(),
        servername: None,
        unverify_ssl: false,
        do_download: false,
        family: 0,
        dns_ip: None,
        dns_label: None,
        original: None,
    };
    r_options.remove_header("proxy-connection");
    r_options.remove_header("proxy-authorization");

    let script_enabled = opts
        .setting
        .pointer("/script/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let script_dir = opts
        .setting
        .get("script")
        .and_then(|v| v.get("dirAbsolutePath"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut ctx = InterceptContext {
        r_options,
        request_headers: head.headers.clone(),
        response_headers: HeaderList::new(),
        response_status: None,
        response_body: None,
        retry_config: None,
        retry_body: None,
        retry_count: 0,
        script_enabled,
        script_dir,
        request_counter: None,
        chosen_backup: None,
    };

    // -------- 请求拦截器
    let interceptors = create_intercepts(&opts.intercepts, &mut ctx, script_enabled);
    for mi in &interceptors {
        if let Some(f) = &mi.request {
            if let InterceptOutcome::Handled = f(&mut ctx) {
                diag.status = ctx.response_status;
                diag.end = "intercepted";
                return write_local_response(reader, writer, &head, &mut ctx).await;
            }
        }
    }

    // -------- 读取请求体（按阈值分流）
    // Content-Length 显式超过阈值的请求体走流式直通（不缓冲在内存、不重试）；
    // 其余保持全量缓冲（重试语义需要 body 重放）
    let stream_threshold = opts
        .setting
        .get("streamBodyThreshold")
        .and_then(|v| v.as_u64())
        .unwrap_or(STREAM_BODY_THRESHOLD);
    let use_stream = head
        .header("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|len| len > stream_threshold);
    let is_upgrade = head.header("upgrade").is_some_and(|v| !v.trim().is_empty());

    let body: Option<Vec<u8>> = if use_stream {
        // 流式路径：body 稍后在 do_request_streaming 中边读边转发
        None
    } else {
        // 读取失败（如超过缓冲上限）后连接内残留未知字节，keep-alive 下会污染下一个请求：
        // 返回 413 并关闭连接是唯一安全的处理
        match read_request_body(reader, &head, MAX_BUFFERED_BODY).await {
            Ok(b) => Some(b),
            Err(e) => {
                diag.fail(413, e.to_string(), "request_body_error");
                log_warn!(
                    "diag conn={} req={} event=request_body_error method={} target={} reason={}",
                    diag.conn,
                    diag.id,
                    head.method,
                    diag.path,
                    crate::util::diag::safe_text(&e.to_string())
                );
                let msg = format!("DevSidecar: request body too large or malformed ({})", e);
                let mut headers = HeaderList::new();
                headers.set("Content-Type", "text/plain; charset=utf-8");
                headers.set("Connection", "close");
                headers.set("Content-Length", &msg.len().to_string());
                write_response_head(writer, 413, &headers).await?;
                writer.write_all(msg.as_bytes()).await?;
                return Ok(false);
            }
        }
    };
    if let Some(b) = &body {
        traffic().add_upload((head.method.len() + path.len() + 96 + b.len()) as u64);
    }

    // -------- DNS / 测速优选
    let dns_started = std::time::Instant::now();
    let (dns_ip, _dns_label) = resolve_upstream_dns(opts, &mut ctx).await;
    diag.dns_ms = Some(crate::util::diag::elapsed_ms(dns_started));

    // -------- 超时
    let timeout = opts
        .setting
        .pointer("/timeoutMapping")
        .and_then(|v| v.get(&ctx.r_options.hostname))
        .and_then(|v| v.get("timeout"))
        .and_then(|v| v.as_u64())
        .or_else(|| opts.setting.get("defaultTimeout").and_then(|v| v.as_u64()))
        .unwrap_or(20_000);

    let allow_tls12 = opts
        .setting
        .get("allowTls12")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let allow_http2 = opts
        .setting
        .get("allowHttp2")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // -------- 上游请求（含重试；流式 body 不参与重试）
    let upstream_started = std::time::Instant::now();
    let upstream_result = match body.as_ref() {
        Some(body) => {
            do_request_with_retry(
                &ctx,
                body,
                dns_ip.clone(),
                timeout,
                allow_tls12,
                allow_http2,
            )
            .await
        }
        None => {
            do_request_streaming(
                reader,
                &head,
                &ctx,
                dns_ip.clone(),
                timeout,
                allow_tls12,
                allow_http2,
            )
            .await
        }
    };
    diag.upstream_ms = Some(crate::util::diag::elapsed_ms(upstream_started));
    diag.retries = ctx.retry_count as u32;
    let mut response = match upstream_result {
        Ok(r) => r,
        Err(e) => {
            diag.fail(502, e.to_string(), "upstream_error");
            log_warn!(
                "diag conn={} req={} event=upstream_error route={} target={}:{}{} retries={} reason={}",
                diag.conn,
                diag.id,
                diag.route,
                diag.host,
                diag.port,
                diag.path,
                diag.retries,
                crate::util::diag::safe_text(&e.to_string())
            );
            let mut headers = HeaderList::new();
            headers.set("Content-Type", "text/plain; charset=utf-8");
            // 响应头会进入客户端日志/错误页，同样需要去掉 URL 查询串等敏感信息
            headers.set(
                "DS-Request-Error",
                &crate::util::diag::safe_text(&e.to_string()),
            );
            headers.set("DS-URL", &crate::util::diag::safe_url(&ctx.r_options.url()));
            headers.set(
                "DS-Target-IP",
                &dns_ip.clone().unwrap_or_else(|| "-".to_string()),
            );
            headers.set("Content-Length", "0");
            write_response_head(writer, 502, &headers).await?;
            return Ok(true);
        }
    };

    // -------- 协议升级（WebSocket 等）：上游同意 101 时透传响应头，
    // 并把客户端连接与上游升级连接做双向隧道
    diag.status = Some(response.status);
    if is_upgrade && response.status == 101 {
        diag.end = "protocol_upgrade";
        return tunnel_upgrade(reader, writer, response).await;
    }

    // -------- 响应拦截器
    let mut upstream = UpstreamHeads {
        status: response.status,
        headers: response.headers.clone(),
    };
    let mut append_head = String::new();
    for mi in &interceptors {
        if let Some(f) = &mi.response {
            if let Some(action) = f(&mut ctx, &mut upstream) {
                append_head.push_str(&action.head);
                if action.stop {
                    break;
                }
            }
        }
    }

    // -------- 组装响应头
    let mut headers = ctx.response_headers.clone();
    for (k, v) in upstream.headers.iter() {
        if v.is_empty() {
            continue;
        }
        let lower = k.to_lowercase();
        if matches!(
            lower.as_str(),
            "connection" | "keep-alive" | "transfer-encoding" | "proxy-authenticate" | "upgrade"
        ) {
            continue;
        }
        // 使用 append 保留同名多值头（如 Set-Cookie）
        headers.append(k, v);
    }
    headers.set("Date", &header_date());

    let content_type = upstream.get("content-type").unwrap_or("").to_string();
    let content_encoding = upstream
        .get("content-encoding")
        .unwrap_or("")
        .to_lowercase();
    let need_inject = !append_head.is_empty() && content_type.to_lowercase().contains("text/html");
    let content_length: Option<u64> = upstream
        .get("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok());
    let status = response.status;
    let has_body = response_has_body(&ctx.r_options.method, status);

    if need_inject && has_body {
        diag.end = "script_injected";
        return inject_and_forward(
            writer,
            &mut response,
            &headers,
            &content_encoding,
            &append_head,
        )
        .await;
    }

    if !has_body {
        // HEAD 的 Content-Length 描述对应 GET 的正文长度，304 也可能携带
        // 所选表示的元数据，因此这两类保留该头但不写正文。1xx/204 不允许
        // 携带 Content-Length；205 显式声明零长度。
        headers.remove("transfer-encoding");
        match status {
            100..=199 | 204 => {
                headers.remove("content-length");
            }
            205 => headers.set("Content-Length", "0"),
            _ => {
                if let Some(len) = content_length {
                    headers.set("Content-Length", &len.to_string());
                }
            }
        }
        write_response_head(writer, response.status, &headers).await?;
        // 不消费上游正文，直接释放响应；无正文语义下绝不能补 chunked 终止块。
        drop(response.body.take());
        drop(response.client.take());
        diag.end = "bodyless_complete";
        return Ok(true);
    }

    match content_length {
        Some(len) => {
            headers.set("Content-Length", &len.to_string());
            write_response_head(writer, response.status, &headers).await?;
        }
        None => {
            headers.remove("content-length");
            headers.set("Transfer-Encoding", "chunked");
            headers.set("Connection", "keep-alive");
            write_response_head(writer, response.status, &headers).await?;
        }
    }

    let result = stream_response_body(writer, response, content_length.is_some()).await;
    diag.end = if result.is_ok() {
        "body_complete"
    } else {
        "body_error"
    };
    result.map(|_| true)
}

/// 响应是否允许携带正文。用于统一无正文状态帧语义，避免 HEAD/204/304
/// 在没有 Content-Length 时被错误转换为 chunked 并写出终止块。
fn response_has_body(method: &str, status: u16) -> bool {
    !method.eq_ignore_ascii_case("HEAD") && !matches!(status, 100..=199 | 204 | 205 | 304)
}

// ------------------------------------------------------------------ 分步实现

/// 拦截器直接响应（Handled）：写出本地响应并消费剩余请求体
async fn write_local_response<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    head: &RequestHead,
    ctx: &mut InterceptContext,
) -> Result<bool> {
    let status = ctx.response_status.unwrap_or(200);
    let body = ctx.response_body.clone().unwrap_or_default();
    let has_body = response_has_body(&head.method, status);
    if matches!(status, 100..=199 | 204 | 304) {
        ctx.response_headers.remove("content-length");
    } else if !matches!(status, 205) {
        // HEAD 保留正文长度元数据，但下面不会写出正文。
        ctx.response_headers
            .set("Content-Length", &body.len().to_string());
    } else {
        ctx.response_headers.set("Content-Length", "0");
    }
    ctx.response_headers.set("Date", &header_date());
    write_response_head(writer, status, &ctx.response_headers).await?;
    if has_body && !body.is_empty() {
        writer.write_all(&body).await?;
    }
    // 消费掉尚未读取的请求体，避免残留字节被当作下一个 keep-alive 请求解析
    if read_request_body(reader, head, MAX_BUFFERED_BODY)
        .await
        .is_ok()
    {
        return Ok(true);
    }
    Ok(false)
}

/// DNS / 测速优选：返回 (指定 IP, 来源标签)，并写入 DS-DNS / DS-SNI 响应头
async fn resolve_upstream_dns(
    opts: &Arc<ServerOptions>,
    ctx: &mut InterceptContext,
) -> (Option<String>, String) {
    let mut dns_ip: Option<String> = None;
    let mut dns_label = String::from("system");
    if !is_ip(&ctx.r_options.hostname) {
        if let Some(speed) = &opts.speed {
            if let Some((ip, name)) = speed.best_ip_with_info(&ctx.r_options.hostname) {
                dns_ip = Some(ip);
                dns_label = format!("{} (speed)", name);
            }
        }
        if dns_ip.is_none() {
            let white =
                match_hostname(&opts.white_list, &ctx.r_options.hostname, "white list").is_some();
            if !white {
                if let Some((dns, family)) =
                    get_dns_and_family(&opts.dns_config, &ctx.r_options.hostname)
                {
                    let ip = dns
                        .lookup(&ctx.r_options.hostname, family, None)
                        .await
                        .unwrap_or_else(|| ctx.r_options.hostname.clone());
                    if is_ip(&ip) {
                        dns_label = format!("{} ({})", dns.dns_name, dns.dns_type);
                        dns_ip = Some(ip);
                    }
                }
            }
        }
        if let Some(ip) = &dns_ip {
            ctx.set_header(
                "DS-DNS",
                // HTTP/1.1 头值仅允许 ASCII/obs-text，避免非 ASCII 字符导致客户端解析异常
                &format!("{} -> {} {}", ctx.r_options.hostname, ip, dns_label),
            );
        }
    }
    ctx.r_options.dns_ip = dns_ip.clone();
    ctx.r_options.dns_label = Some(dns_label.clone());
    if let Some(sni) = ctx.r_options.servername.clone() {
        if !sni.is_empty() {
            ctx.set_header("DS-SNI", &sni);
        }
    }
    (dns_ip, dns_label)
}

/// 脚本注入路径：缓冲（有限）上游 body，解压后把脚本插入 </head> 之前
async fn inject_and_forward<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &mut UpstreamResponse,
    headers: &HeaderList,
    content_encoding: &str,
    append_head: &str,
) -> Result<bool> {
    let mut buffer = Vec::new();
    let mut too_large = false;
    if let Some(body) = response.body.take() {
        let mut body = body;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(f) => {
                    if let Some(data) = f.data_ref() {
                        traffic().add_download(data.len() as u64);
                        if buffer.len() + data.len() <= MAX_INJECT_BODY {
                            buffer.extend_from_slice(data);
                        } else {
                            too_large = true;
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
    let _ = too_large;
    decompress_in_place(&mut buffer, content_encoding);
    let text = String::from_utf8_lossy(&buffer).to_string();
    let injected = inject_head(&text, append_head);
    let mut headers = headers.clone();
    headers.remove("content-length");
    headers.remove("content-encoding");
    headers.set("Content-Length", &injected.len().to_string());
    write_response_head(writer, response.status, &headers).await?;
    writer.write_all(injected.as_bytes()).await?;
    Ok(true)
}

/// 流式回写响应体：有 Content-Length 时原样透传，否则以 chunked 编码输出
async fn stream_response_body<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut response: UpstreamResponse,
    has_length: bool,
) -> Result<()> {
    let mut body_error: Option<String> = None;
    if let Some(body) = response.body.take() {
        let mut body = body;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(f) => {
                    let Some(data) = f.data_ref() else {
                        // trailers 等非数据帧：客户端不要求 trailers，跳过
                        continue;
                    };
                    // 空 DATA 帧不携带数据。chunked 编码下若按普通 chunk 写出会变成
                    // `0\r\n\r\n`（终止块），导致响应被提前结束、后续字节被客户端当作
                    // 新响应的状态行解析（curl 报 "Invalid status line"）
                    if data.is_empty() {
                        continue;
                    }
                    traffic().add_download(data.len() as u64);
                    if has_length {
                        writer.write_all(data).await?;
                    } else {
                        writer
                            .write_all(format!("{:x}\r\n", data.len()).as_bytes())
                            .await?;
                        writer.write_all(data).await?;
                        writer.write_all(b"\r\n").await?;
                    }
                }
                Err(e) => {
                    body_error = Some(e.to_string());
                    break;
                }
            }
        }
    }
    // 到这里调用方已确认该响应允许携带正文。无 Content-Length 时使用
    // chunked，必须且只能写一个终止块；上游读取中断时**不能**补终止块，
    // 否则客户端会把截断的响应当作完整的（git 报 `expected flush after
    // ref listing`），应由下面的 bail 关闭连接。
    if body_error.is_none() && !has_length {
        writer.write_all(b"0\r\n\r\n").await?;
    }
    // 保持 hyper client 存活到响应结束
    drop(response.client.take());
    // 响应体中途失败：关闭连接，让客户端明确感知失败并可重试
    if let Some(e) = body_error {
        anyhow::bail!("上游响应体读取中断: {}", e);
    }
    Ok(())
}

// ------------------------------------------------------------------ 重试策略

/// 无显式重试规则时的兜底尝试次数：幂等请求允许再试一次（瞬时连接失败可自愈），
/// 非幂等请求保持单次，避免重复产生副作用
fn default_attempts(method: &str) -> u32 {
    if default_retry_methods().contains(&method.to_uppercase()) {
        2
    } else {
        1
    }
}

/// 发起请求（含重试逻辑）
async fn do_request_with_retry(
    ctx: &InterceptContext,
    body: &[u8],
    dns_ip: Option<String>,
    timeout_ms: u64,
    allow_tls12: bool,
    allow_http2: bool,
) -> Result<UpstreamResponse> {
    let retry = ctx.retry_config.clone();
    let method = ctx.r_options.method.to_uppercase();
    // 有重试规则时按其 times 重试；无规则时也给「幂等方法的建连失败」一次机会
    // （对齐原版重试语义：瞬时连接失败可自愈，同时不重复非幂等请求）
    let max_attempts = match &retry {
        Some(r) => r.times + 1,
        None => default_attempts(&method),
    };
    let mut last_error: Option<anyhow::Error> = None;

    for attempt in 0..max_attempts {
        let outcome = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            do_request(ctx, body, dns_ip.clone(), allow_tls12, allow_http2),
        )
        .await;

        match outcome {
            Ok(Ok(resp)) => {
                let should_retry = match &retry {
                    Some(r) => {
                        attempt + 1 < max_attempts
                            && r.statuses.contains(&resp.status)
                            && r.methods.contains(&method)
                    }
                    None => false,
                };
                if !should_retry {
                    return Ok(resp);
                }
                log_warn!(
                    "请求返回 {}，开始第 {} 次重试: {}",
                    resp.status,
                    attempt + 1,
                    crate::util::diag::safe_url(&ctx.r_options.url())
                );
                drop(resp);
                last_error = None;
            }
            Ok(Err(e)) => {
                if attempt + 1 < max_attempts {
                    log_info!(
                        "请求失败，开始第 {} 次重试: {} -> {}",
                        attempt + 1,
                        crate::util::diag::safe_url(&ctx.r_options.url()),
                        crate::util::diag::safe_text(&e.to_string())
                    );
                }
                last_error = Some(e);
            }
            Err(_) => {
                last_error = Some(anyhow!("请求超时"));
                // 无显式重试规则时超时不重试：长轮询类端点会把等待时间成倍拉长
                if retry.is_none() {
                    break;
                }
            }
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("请求失败")))
}

/// 单次上游请求（只读取响应头，body 延迟消费）
async fn do_request(
    ctx: &InterceptContext,
    body: &[u8],
    dns_ip: Option<String>,
    allow_tls12: bool,
    allow_http2: bool,
) -> Result<UpstreamResponse> {
    let r = &ctx.r_options;
    let https = r.protocol == "https:";
    let ip = dns_ip.unwrap_or_else(|| r.hostname.clone());

    // 升级请求（WebSocket 等）：连接将被协议接管，必须用一次性客户端；
    // 其余走池化客户端复用连接
    let is_upgrade = r.header("upgrade").is_some_and(|v| !v.trim().is_empty());

    let target = UpstreamTarget {
        https,
        host: r.hostname.clone(),
        ip,
        port: r.port,
        sni: r.servername.clone().filter(|s| !s.is_empty()),
        verify: !r.unverify_ssl,
        allow_tls12,
        // 升级握手依赖 HTTP/1.1；明文连接不协商 h2
        allow_http2: allow_http2 && https && !is_upgrade,
    };
    let client = if is_upgrade {
        Arc::new(ClientPool::build_oneshot(target.clone())?)
    } else {
        // 池化客户端：相同 (host, ip, port, sni, verify, tls12) 复用同一 hyper Client，
        // 其内部连接池自动复用空闲连接，免去重复 TCP + TLS 握手
        let key = UpstreamKey::from_target(&target);
        client_pool().get_or_build(key)?
    };

    // hyper 客户端要求绝对 URI；authority 与 Host 头保持一致（见 build_upstream_uri）
    let uri = build_upstream_uri(r, https);

    let mut builder = ::http::Request::builder()
        .method(r.method.as_str())
        .uri(&uri)
        .version(::http::Version::HTTP_11);

    // host 头不转发，由 hyper 按 URI 生成（见 forward_request_header 注释）
    for (k, v) in &r.headers {
        let lower = k.to_lowercase();
        if !forward_request_header(&lower, is_upgrade) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            ::http::HeaderName::from_bytes(k.as_bytes()),
            ::http::HeaderValue::from_str(v),
        ) {
            builder = builder.header(name, value);
        }
    }

    let req = builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|e| anyhow!("构造请求失败(uri={}): {}", uri, e))?;

    // hyper 只向外暴露 "client error (Connect)" 这类笼统信息，这里把 source 链
    // （DNS / TCP / TLS 的具体失败原因）拼进错误，便于从日志定位失败阶段
    let mut response = client.request(req).await.map_err(|e| {
        let mut msg = e.to_string();
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            msg.push_str(" -> ");
            msg.push_str(&s.to_string());
            src = s.source();
        }
        anyhow!(msg)
    })?;
    let status = response.status().as_u16();
    let mut headers = Vec::new();
    for (name, value) in response.headers().iter() {
        headers.push((
            name.as_str().to_string(),
            value.to_str().unwrap_or("").to_string(),
        ));
    }
    // 升级请求的 101 响应携带 OnUpgrade 句柄，用于接管上游连接
    let on_upgrade = response
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>();
    let body = response.into_body();

    Ok(UpstreamResponse {
        status,
        headers,
        body: Some(body),
        on_upgrade,
        client: Some(ClientHolder::Buffered(client)),
    })
}

// ------------------------------------------------------------------ 流式 / 升级

/// ReaderStream 字节块 → http_body Frame（作为 fn pointer 以固定 StreamClient 的类型）
fn frame_of_chunk(
    res: Result<Bytes, std::io::Error>,
) -> Result<http_body::Frame<Bytes>, std::io::Error> {
    res.map(http_body::Frame::data)
}

/// 流式上游请求：请求体超过阈值时用 duplex 管道把客户端 body 直通转发到上游，
/// 不在内存缓冲、不参与重试。函数返回时请求体必已读完（reader 已归还）
async fn do_request_streaming<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    head: &RequestHead,
    ctx: &InterceptContext,
    dns_ip: Option<String>,
    timeout_ms: u64,
    allow_tls12: bool,
    allow_http2: bool,
) -> Result<UpstreamResponse> {
    let r = &ctx.r_options;
    let https = r.protocol == "https:";
    let ip = dns_ip.unwrap_or_else(|| r.hostname.clone());

    let target = UpstreamTarget {
        https,
        host: r.hostname.clone(),
        ip,
        port: r.port,
        sni: r.servername.clone().filter(|s| !s.is_empty()),
        verify: !r.unverify_ssl,
        allow_tls12,
        allow_http2: allow_http2 && https,
    };
    let key = UpstreamKey::from_target(&target);
    let client = client_pool().get_or_build_streaming(key)?;

    // authority 与 Host 头保持一致（见 build_upstream_uri）
    let uri = build_upstream_uri(r, https);

    let mut builder = ::http::Request::builder()
        .method(r.method.as_str())
        .uri(&uri)
        .version(::http::Version::HTTP_11);

    // host 头不转发，由 hyper 按 URI 生成（流式路径无升级握手）
    for (k, v) in &r.headers {
        let lower = k.to_lowercase();
        if !forward_request_header(&lower, false) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            ::http::HeaderName::from_bytes(k.as_bytes()),
            ::http::HeaderValue::from_str(v),
        ) {
            builder = builder.header(name, value);
        }
    }

    // duplex 管道桥接：客户端 body → 管道写端 → ReaderStream（'static body）
    let (pipe_r, mut pipe_w) = tokio::io::duplex(64 * 1024);
    let mapper: fn(
        Result<Bytes, std::io::Error>,
    ) -> Result<http_body::Frame<Bytes>, std::io::Error> = frame_of_chunk;
    let stream = tokio_util::io::ReaderStream::new(pipe_r).map(mapper);
    let body = http_body_util::StreamBody::new(stream);
    let req = builder
        .body(body)
        .map_err(|e| anyhow!("构造请求失败(uri={}): {}", uri, e))?;

    // 同时搬运请求体并发送请求；请求体发完后关闭管道写端（向 ReaderStream 发出 EOF）
    let copy_body = async {
        let res = copy_request_body_to(reader, head, &mut pipe_w).await;
        drop(pipe_w);
        res
    };
    let send = client.request(req);
    let (copy_res, send_res) = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
        tokio::join!(copy_body, send)
    })
    .await
    .map_err(|_| anyhow!("请求超时"))?;
    copy_res?;

    let mut response = send_res.map_err(|e| {
        let mut msg = e.to_string();
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            msg.push_str(" -> ");
            msg.push_str(&s.to_string());
            src = s.source();
        }
        anyhow!(msg)
    })?;
    let status = response.status().as_u16();
    let mut headers = Vec::new();
    for (name, value) in response.headers().iter() {
        headers.push((
            name.as_str().to_string(),
            value.to_str().unwrap_or("").to_string(),
        ));
    }
    let on_upgrade = response
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>();
    let body = response.into_body();

    Ok(UpstreamResponse {
        status,
        headers,
        body: Some(body),
        on_upgrade,
        client: Some(ClientHolder::Streaming(client)),
    })
}

/// 协议升级隧道（WebSocket 等）：原样透传 101 响应头，随后在客户端连接
/// 与上游升级连接之间做双向字节透传。隧道结束后关闭连接
async fn tunnel_upgrade<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    mut response: UpstreamResponse,
) -> Result<bool> {
    let Some(on_upgrade) = response.on_upgrade.take() else {
        // 上游返回 101 但未提供升级句柄（不应发生），回 502
        log_warn!("上游返回 101 但缺少升级句柄");
        let mut headers = HeaderList::new();
        headers.set("Content-Type", "text/plain; charset=utf-8");
        headers.set("Content-Length", "0");
        write_response_head(writer, 502, &headers).await?;
        return Ok(false);
    };

    // 先等待上游连接升级完成，再透传 101 头，避免客户端在隧道就绪前发数据
    // （Upgraded 实现的是 hyper 的 Read/Write，需用 TokioIo 适配为 tokio 流）
    let mut upgraded = crate::proxy::connector::TokioIo::new(
        on_upgrade
            .await
            .map_err(|e| anyhow!("上游升级失败: {}", e))?,
    );

    let mut head_out = format!("HTTP/1.1 101 {}\r\n", status_reason(101));
    for (k, v) in &response.headers {
        head_out.push_str(&format!("{}: {}\r\n", k, v));
    }
    head_out.push_str("\r\n");
    writer.write_all(head_out.as_bytes()).await?;
    writer.flush().await?;
    log_debug!("协议升级隧道已建立: {} 字节响应头已透传", head_out.len());

    // 双向透传（连接生命周期由两端决定，任一方向结束即返回）
    let (mut ur, mut uw) = tokio::io::split(&mut upgraded);
    let c1 = tokio::io::copy(reader, &mut uw);
    let c2 = tokio::io::copy(&mut ur, writer);
    let (r1, r2) = tokio::join!(c1, c2);
    if let (Ok(up), Ok(down)) = (&r1, &r2) {
        log_debug!("升级隧道结束: 上行 {} 字节, 下行 {} 字节", up, down);
    }
    let _ = (r1, r2);
    Ok(false)
}

// ------------------------------------------------------------------ 工具函数

/// 构造 hyper 要求的绝对 URI。
/// authority 必须与 Host 头保持一致（默认端口不带后缀）：
/// HTTP/2 下 hyper 用 URI 的 authority 生成 `:authority` 伪头，若与转发的
/// Host 头不一致（例如带 `:443` 而客户端 Host 不带），部分上游 CDN/网关
/// 会因校验失败返回 400（npmmirror 等实测如此）
fn build_upstream_uri(r: &RequestOptions, https: bool) -> String {
    // 拦截器改写后的绝对 URI：原样使用（Host 头已由拦截器同步改写）
    if r.path.starts_with("http://") || r.path.starts_with("https://") {
        return r.path.clone();
    }
    let scheme = if https { "https" } else { "http" };
    let default_port = if https { 443 } else { 80 };
    let authority = match r.header("host") {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => {
            if r.port == default_port {
                r.hostname.clone()
            } else {
                format!("{}:{}", r.hostname, r.port)
            }
        }
    };
    format!("{}://{}{}", scheme, authority, r.path)
}

/// 请求头转发过滤：返回 false 表示该头不转发到上游。
/// - `host`：不转发。h1 下 hyper_util 按 URI authority 自动补齐同值 Host
///   （默认端口不带后缀）；h2 下仅保留 `:authority` 伪头。若转发 host，
///   h2 请求会同时携带 `:authority` 与 host——RFC 9113 §8.3.1 允许严格
///   服务器拒绝，部分 CDN/网关即使值一致也返回 400（npmmirror 等实测）
/// - 连接管理头（connection/keep-alive/proxy-*）：非升级请求一律剥离；
///   升级请求保留 `Connection: Upgrade`（hyper 依赖它识别升级握手）
/// - `expect`：100-continue 由上游直发，代理不透传
fn forward_request_header(lower: &str, is_upgrade: bool) -> bool {
    if matches!(
        lower,
        "host" | "proxy-connection" | "proxy-authorization" | "keep-alive" | "expect"
    ) {
        return false;
    }
    if lower == "connection" && !is_upgrade {
        return false;
    }
    true
}

fn resolve_target(head: &RequestHead, ssl: bool) -> (String, String, u16, String) {
    if head.target.starts_with("http://") || head.target.starts_with("https://") {
        return parse_target(&head.target, ssl);
    }
    let host_header = head.header("host").unwrap_or("").to_string();
    let (host, port_opt) = split_host_port(&host_header);
    let protocol = if ssl { "https:" } else { "http:" };
    let port = port_opt.unwrap_or(if ssl { 443 } else { 80 });
    (protocol.to_string(), host, port, head.target.clone())
}

fn header_date() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn decompress_in_place(data: &mut Vec<u8>, encoding: &str) {
    if encoding.is_empty() || encoding == "identity" {
        return;
    }
    use std::io::Read;
    if encoding.contains("gzip") {
        let mut out = Vec::new();
        if flate2::read::GzDecoder::new(&data[..])
            .read_to_end(&mut out)
            .is_ok()
        {
            *data = out;
        }
    } else if encoding.contains("deflate") {
        let mut out = Vec::new();
        if flate2::read::DeflateDecoder::new(&data[..])
            .read_to_end(&mut out)
            .is_ok()
        {
            *data = out;
        }
    }
}

fn inject_head(html: &str, append: &str) -> String {
    let lower = html.to_lowercase();
    match lower.find("</head>") {
        Some(idx) => {
            let mut out = String::with_capacity(html.len() + append.len());
            out.push_str(&html[..idx]);
            out.push_str(append);
            out.push_str(&html[idx..]);
            out
        }
        None => {
            log_warn!("缺少 </head> 标记，脚本将插入到响应头部");
            format!("{}{}", append, html)
        }
    }
}

/// 释放上游连接
impl Drop for UpstreamResponse {
    fn drop(&mut self) {
        if let Some(body) = self.body.take() {
            drop(body);
        }
        if let Some(client) = self.client.take() {
            drop(client);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 无正文语义：HEAD 与 1xx/204/205/304 不得写正文或 chunked 终止块
    #[test]
    fn response_body_semantics_cover_bodyless_responses() {
        for status in [100, 101, 199, 204, 205, 304] {
            assert!(!response_has_body("GET", status), "{} 不应有正文", status);
        }
        assert!(!response_has_body("head", 200));
        assert!(!response_has_body("Head", 304));
        assert!(response_has_body("GET", 200));
        assert!(!response_has_body("POST", 304));
    }

    /// 无重试规则时：幂等方法再试一次，非幂等方法只试一次
    #[test]
    fn default_attempts_only_retries_idempotent_methods() {
        for m in ["get", "GET", "Head", "options"] {
            assert_eq!(default_attempts(m), 2, "{} 应允许一次兜底重试", m);
        }
        for m in ["POST", "put", "delete", "PATCH"] {
            assert_eq!(default_attempts(m), 1, "{} 不应默认重试", m);
        }
    }

    fn r_options(host: Option<&str>, hostname: &str, port: u16, path: &str) -> RequestOptions {
        let mut headers = Vec::new();
        if let Some(h) = host {
            headers.push(("Host".to_string(), h.to_string()));
        }
        RequestOptions {
            protocol: "https:".to_string(),
            method: "GET".to_string(),
            hostname: hostname.to_string(),
            port,
            path: path.to_string(),
            headers,
            servername: None,
            unverify_ssl: false,
            do_download: false,
            family: 0,
            dns_ip: None,
            dns_label: None,
            original: None,
        }
    }

    /// URI authority 必须与 Host 头一致：客户端 Host 不带默认端口时，
    /// URI 不得带 `:443`（否则 h2 的 :authority 与 host 头冲突，部分 CDN 返回 400）
    #[test]
    fn upstream_uri_authority_matches_host_header() {
        // Host 头不带端口 + 默认端口 → URI 不带 :443（npmmirror 400 场景）
        let r = r_options(
            Some("registry.npmmirror.com"),
            "registry.npmmirror.com",
            443,
            "/@scope%2fpkg",
        );
        assert_eq!(
            build_upstream_uri(&r, true),
            "https://registry.npmmirror.com/@scope%2fpkg"
        );

        // Host 头带非默认端口 → 原样保留
        let r = r_options(Some("example.test:8443"), "example.test", 8443, "/x");
        assert_eq!(build_upstream_uri(&r, true), "https://example.test:8443/x");

        // 无 Host 头 + 默认端口 → 不带端口
        let r = r_options(None, "a.test", 443, "/y");
        assert_eq!(build_upstream_uri(&r, true), "https://a.test/y");

        // 无 Host 头 + 非默认端口 → 带端口
        let r = r_options(None, "a.test", 8443, "/y");
        assert_eq!(build_upstream_uri(&r, true), "https://a.test:8443/y");

        // http 协议默认端口
        let r = r_options(None, "b.test", 80, "/z");
        assert_eq!(build_upstream_uri(&r, false), "http://b.test/z");

        // 拦截器改写后的绝对 URI 原样使用
        let r = r_options(None, "a.test", 443, "https://mirror.example.com/p");
        assert_eq!(build_upstream_uri(&r, true), "https://mirror.example.com/p");
    }

    /// host 头一律不转发（h2 下 :authority 与 host 共存会被严格服务器拒绝，
    /// h1 下 hyper_util 按 URI 自动补齐）；连接管理头仅升级请求保留 connection
    #[test]
    fn request_header_forwarding_filter() {
        // host 及连接管理头 / expect 一律不转发
        for h in [
            "host",
            "connection",
            "proxy-connection",
            "proxy-authorization",
            "keep-alive",
            "expect",
        ] {
            assert!(
                !forward_request_header(h, false),
                "{} 不应转发（非升级请求）",
                h
            );
        }
        // 升级请求保留 Connection: Upgrade（hyper 依赖它识别升级握手），
        // 但其余连接管理头仍剥离
        assert!(forward_request_header("connection", true));
        assert!(!forward_request_header("host", true));
        assert!(!forward_request_header("keep-alive", true));
        // 普通头原样转发
        for h in ["content-type", "user-agent", "accept-encoding", "cookie"] {
            assert!(forward_request_header(h, false), "{} 应转发", h);
            assert!(forward_request_header(h, true), "{} 应转发（升级）", h);
        }
    }
}
