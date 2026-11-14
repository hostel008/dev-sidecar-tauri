//! 带注释与尾逗号的 JSON(JSONC/JSON5 子集) 解析，用于兼容配置/远程配置文件

/// 去除行注释、块注释（不处理字符串内的注释符号已做转义保护）
pub fn strip_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let len = bytes.len();
    let mut in_string = false;
    let mut string_quote = '"';
    while i < len {
        let c = bytes[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < len {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if c == string_quote {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' | '\'' => {
                in_string = true;
                string_quote = c;
                out.push('"');
            }
            '/' if i + 1 < len && bytes[i + 1] == '/' => {
                while i < len && bytes[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < len && bytes[i + 1] == '*' => {
                i += 2;
                while i + 1 < len && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(len);
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// 去除对象和数组尾部的多余逗号
fn strip_trailing_commas(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let len = chars.len();
    let mut in_string = false;
    let mut quote = '"';
    while i < len {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < len {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == quote {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
            quote = '"';
            out.push(c);
            i += 1;
            continue;
        }
        if c == ',' {
            // 向后查找下一个非空白字符
            let mut j = i + 1;
            while j < len && chars[j].is_whitespace() {
                j += 1;
            }
            if j < len && (chars[j] == '}' || chars[j] == ']') {
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// 解析宽松 JSON
pub fn parse(input: &str) -> anyhow::Result<serde_json::Value> {
    let cleaned = strip_trailing_commas(&strip_comments(input));
    match serde_json::from_str::<serde_json::Value>(&cleaned) {
        Ok(v) => Ok(v),
        Err(e) => anyhow::bail!(
            "JSON 解析失败: {}, 内容前 200 字符: {}",
            e,
            &cleaned.chars().take(200).collect::<String>()
        ),
    }
}

pub fn stringify(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}
