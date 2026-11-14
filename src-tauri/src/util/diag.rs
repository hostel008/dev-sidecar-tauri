use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// 连接 / 请求标识：只用于把同一条链路的多条日志串起来，不含任何用户数据。
pub fn next_id(prefix: &str) -> String {
    format!("{}-{:x}", prefix, NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

pub fn elapsed_ms(start: Instant) -> u128 {
    start.elapsed().as_millis()
}

/// 日志/诊断里的 URL 只保留 scheme、host、port、path：
/// 查询串常包含 token/code/邮箱等敏感信息，必须丢弃；userinfo 同样丢弃。
pub fn safe_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            u.set_query(None);
            u.set_fragment(None);
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string()
        }
        Err(_) => safe_path(raw),
    }
}

/// 错误文本脱敏：错误里常带完整 URL（含查询串/token），逐个 token 改写。
/// 只用于日志，不改变返回给调用方的错误。
pub fn safe_text(raw: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for token in raw.split_whitespace() {
        if token.contains("://") {
            let trimmed =
                token.trim_matches(|c: char| matches!(c, '(' | ')' | '[' | ']' | ',' | ';' | '"'));
            parts.push(safe_url(trimmed));
        } else {
            parts.push(token.to_string());
        }
    }
    parts.join(" ").chars().take(600).collect()
}

/// 仅保留路径部分，供没有完整 URL 的 CONNECT / 请求行使用。
pub fn safe_path(raw: &str) -> String {
    let no_fragment = raw.split('#').next().unwrap_or("");
    let no_query = no_fragment.split('?').next().unwrap_or("");
    no_query.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_never_keep_query_tokens() {
        assert_eq!(
            safe_url("https://user:pass@login.example.com/oauth?code=secret#frag"),
            "https://login.example.com/oauth"
        );
        let text = safe_text(
            "error for url (https://registry.example.com/pkg?token=abc) and https://a.example/x?y=1",
        );
        assert!(!text.contains("secret"));
        assert!(!text.contains("token="));
        assert!(!text.contains("?y="));
        assert!(text.contains("https://registry.example.com/pkg"));
        assert_eq!(safe_path("/a/b?c=d#e"), "/a/b");
    }
}
