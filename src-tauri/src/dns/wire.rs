//! DNS 报文编解码（RFC1035 最小实现）

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub struct Answer {
    #[allow(dead_code)]
    pub name: String,
    pub rtype: u16,
    pub data: Vec<u8>,
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// 构造查询报文
pub fn encode_query(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    // flags: RD=1
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut out, hostname);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    if off + 2 > buf.len() {
        return None;
    }
    Some(u16::from_be_bytes([buf[off], buf[off + 1]]))
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    if off + 4 > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

/// 跳过（并重建）一个压缩域名
fn read_name(buf: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = off;
    let mut jumps = 0;
    loop {
        if off >= buf.len() {
            return None;
        }
        let len = buf[off];
        if len & 0xC0 == 0xC0 {
            let ptr = (read_u16(buf, off)? & 0x3FFF) as usize;
            if ptr >= buf.len() {
                return None;
            }
            if jumps == 0 {
                end = off + 2;
            }
            jumps += 1;
            if jumps > 10 {
                return None;
            }
            off = ptr;
            continue;
        }
        if len == 0 {
            if jumps == 0 {
                end = off + 1;
            }
            break;
        }
        let start = off + 1;
        let stop = start + len as usize;
        if stop > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[start..stop]).to_string());
        off = stop;
        if jumps == 0 {
            end = stop;
        }
    }
    Some((labels.join("."), end))
}

/// 解析响应报文中的 answers
pub fn parse_response(buf: &[u8]) -> anyhow::Result<Vec<Answer>> {
    if buf.len() < 12 {
        anyhow::bail!("DNS 响应过短");
    }
    let ancount = read_u16(buf, 6).ok_or_else(|| anyhow::anyhow!("响应头损坏"))?;
    let mut off = 12usize;

    // 跳过 questions
    let qdcount = read_u16(buf, 4).unwrap_or(0);
    for _ in 0..qdcount {
        let (_, next) = read_name(buf, off).ok_or_else(|| anyhow::anyhow!("question 解析失败"))?;
        off = next + 4; // QTYPE + QCLASS
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (name, next) =
            read_name(buf, off).ok_or_else(|| anyhow::anyhow!("answer 名称解析失败"))?;
        off = next;
        let rtype = read_u16(buf, off).ok_or_else(|| anyhow::anyhow!("answer type 解析失败"))?;
        off += 2 + 2; // type + class
        let _ttl = read_u32(buf, off).ok_or_else(|| anyhow::anyhow!("answer ttl 解析失败"))?;
        off += 4;
        let rdlength =
            read_u16(buf, off).ok_or_else(|| anyhow::anyhow!("answer rdlength 解析失败"))?;
        off += 2;
        let rend = off + rdlength as usize;
        if rend > buf.len() {
            break;
        }
        let data = buf[off..rend].to_vec();
        answers.push(Answer { name, rtype, data });
        off = rend;
    }
    Ok(answers)
}

/// 将 answer 的 RDATA 转成字符串 IP（仅 A / AAAA）
pub fn answer_to_ip(answer: &Answer) -> Option<String> {
    match answer.rtype {
        TYPE_A if answer.data.len() == 4 => Some(format!(
            "{}.{}.{}.{}",
            answer.data[0], answer.data[1], answer.data[2], answer.data[3]
        )),
        TYPE_AAAA if answer.data.len() == 16 => Some(
            (0..8)
                .map(|i| {
                    format!(
                        "{:x}",
                        u16::from_be_bytes([answer.data[i * 2], answer.data[i * 2 + 1]])
                    )
                })
                .collect::<Vec<String>>()
                .join(":"),
        ),
        _ => None,
    }
}
