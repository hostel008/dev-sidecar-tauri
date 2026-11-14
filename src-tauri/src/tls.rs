//! CA 根证书生成 / 加载，以及按域名签发的 MITM 伪装证书

use anyhow::Result;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// 与 node-forge 版本保持一致的证书主体信息
fn dev_sidecar_dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::CountryName, "CN");
    dn.push(DnType::StateOrProvinceName, "GuangDong");
    dn.push(DnType::LocalityName, "ShenZhen");
    dn.push(DnType::OrganizationName, "dev-sidecar");
    dn.push(
        DnType::OrganizationalUnitName,
        "https://github.com/docmirror/dev-sidecar",
    );
    dn
}

fn now_offset() -> time::OffsetDateTime {
    time::OffsetDateTime::from(std::time::SystemTime::now())
}

/// 收紧 CA 私钥文件权限：仅当前用户可读写。
/// - Unix：显式 0600
/// - Windows：移除继承的 ACL 并仅授予当前用户完全控制（用户目录下的文件
///   默认继承用户级 ACL，此处显式收紧防呆）；失败仅告警，不阻断启动
fn restrict_key_file_permissions(key_path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(key_path, perm) {
            log_warn!("设置私钥文件权限失败 {}: {}", key_path.display(), e);
        }
    }
    #[cfg(windows)]
    {
        // icacls 为 Windows 标准组件：/inheritance:r 移除继承 ACL，
        // /grant:r 仅授予当前用户完全控制
        let username = std::env::var("USERNAME").unwrap_or_default();
        if username.is_empty() {
            log_warn!("无法确定当前用户名，跳过私钥文件 ACL 收紧");
            return;
        }
        let path = key_path.to_string_lossy().to_string();
        let grant = format!("{}:F", username);
        let output = std::process::Command::new("icacls")
            .arg(&path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant)
            .output();
        match output {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                log_warn!(
                    "收紧私钥文件 ACL 失败（icacls）: {} -> {}",
                    key_path.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Err(e) => {
                log_warn!("调用 icacls 失败: {}", e);
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = key_path;
    }
}

fn build_ca_params(
    common_name: &str,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = dev_sidecar_dn(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.use_authority_key_identifier_extension = true;
    params.not_before = not_before;
    params.not_after = not_after;
    params
}

/// 用于跳过证书校验的验证器
#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _drr: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _drr: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // 按 ring provider 的签名验证算法动态生成，与默认 provider 的
        // 能力保持一致，避免硬编码列表缺项导致握手失败
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构建 upstream 的 TLS 客户端配置
pub fn build_client_config(
    verify: bool,
    allow_tls12: bool,
    allow_http2: bool,
) -> anyhow::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let public_roots = load_public_root_certs();
    let (added, ignored) = roots.add_parsable_certificates(public_roots);
    if added == 0 {
        // 平台证书库不可用时的兜底：webpki-roots 只含锚点，能完成校验但无法导出 PEM。
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        log_warn!("平台根证书不可用，upstream 校验退回内置公共根");
    }
    if ignored > 0 {
        log_warn!("有 {} 张平台根证书无法解析，已忽略", ignored);
    }

    let versions: &[&rustls::SupportedProtocolVersion] = if allow_tls12 {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = || {
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
    };
    let mut cfg = if verify {
        builder()?
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        builder()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };
    if allow_http2 {
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    } else {
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    log_info!(
        "TLS 客户端配置: verify={} tls12={} http2={} 根证书={}",
        verify,
        allow_tls12,
        allow_http2,
        added
    );
    Ok(cfg)
}

type ClientConfigCache = HashMap<(bool, bool, bool), Arc<rustls::ClientConfig>>;
static CLIENT_CONFIGS: Lazy<Mutex<ClientConfigCache>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// 按（是否校验 / 是否允许 TLS1.2 / 是否协商 h2）缓存 ClientConfig。
/// 构建一次要解析上百张根证书，连接级复用避免每请求重复开销。
pub fn cached_client_config(
    verify: bool,
    allow_tls12: bool,
    allow_http2: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    let key = (verify, allow_tls12, allow_http2);
    if let Some(cfg) = CLIENT_CONFIGS.lock().get(&key) {
        return Ok(cfg.clone());
    }
    let cfg = Arc::new(build_client_config(verify, allow_tls12, allow_http2)?);
    CLIENT_CONFIGS.lock().insert(key, cfg.clone());
    Ok(cfg)
}

pub struct CertificateAuthority {
    ca_cert: Certificate,
    ca_key_pair: KeyPair,
    /// 复用的叶子私钥：所有 MITM 伪装证书共用（同一 CA 签发下安全等价，
    /// 私钥不出进程），避免每个新域名握手时都要生成密钥对
    leaf_key: KeyPair,
    cache: Mutex<lru::LruCache<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    /// 加载已有根证书，或重新生成并落盘
    pub fn init(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
        cache_size: usize,
    ) -> Result<Self> {
        let leaf_key = KeyPair::generate()?;

        if let (Ok(cert_pem), Ok(key_pem)) = (
            std::fs::read_to_string(cert_path),
            std::fs::read_to_string(key_path),
        ) {
            if !cert_pem.is_empty() && !key_pem.is_empty() {
                match KeyPair::from_pem(&key_pem) {
                    Ok(key_pair) => {
                        let ca_cert = build_ca_params(
                            "DevSidecar CA",
                            now_offset() - time::Duration::HOUR,
                            now_offset() + time::Duration::days(365 * 20),
                        )
                        .self_signed(&key_pair)?;
                        log_info!("已加载根证书: {}", cert_path.display());
                        return Ok(CertificateAuthority {
                            ca_cert,
                            ca_key_pair: key_pair,
                            leaf_key,
                            cache: Mutex::new(lru::LruCache::new(
                                NonZeroUsize::new(cache_size.max(1)).unwrap(),
                            )),
                        });
                    }
                    Err(e) => log_warn!("加载根证书私钥失败，将重新生成: {}", e),
                }
            }
        }

        let key_pair = KeyPair::generate()?;
        let not_before = now_offset() - time::Duration::HOUR;
        let not_after = now_offset() + time::Duration::days(365 * 20);
        let ca_cert =
            build_ca_params("DevSidecar CA", not_before, not_after).self_signed(&key_pair)?;

        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(cert_path, ca_cert.pem())?;
        std::fs::write(key_path, key_pair.serialize_pem())?;
        restrict_key_file_permissions(key_path);
        log_info!(
            "生成 CA 证书文件成功，共2个文件: {}, {}",
            cert_path.display(),
            key_path.display()
        );

        Ok(CertificateAuthority {
            ca_cert,
            ca_key_pair: key_pair,
            leaf_key,
            cache: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(cache_size.max(1)).unwrap(),
            )),
        })
    }

    /// 为指定主机名签发证书，并构建 rustls ServerConfig
    pub fn get_server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        if let Some(cfg) = self.cache.lock().get(hostname) {
            return Ok(cfg.clone());
        }

        let (cert_der, key_der) = self.issue(hostname)?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;

        let config = Arc::new(config);
        let mut guard = self.cache.lock();
        guard.put(hostname.to_string(), config.clone());
        Ok(config)
    }

    fn issue(&self, hostname: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut names: Vec<String> = Vec::new();
        names.push(hostname.to_string());
        // 父域名与其通配形式，覆盖子资源域名
        if let Some(dot) = hostname.find('.') {
            let parent = &hostname[dot + 1..];
            if !parent.is_empty() && parent.contains('.') {
                names.push(parent.to_string());
                names.push(format!("*.{}", parent));
            }
        }

        let mut params =
            CertificateParams::new(names.clone()).unwrap_or_else(|_| CertificateParams::default());
        params.subject_alt_names = names
            .iter()
            .map(|name| match name.parse::<std::net::IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName(name.clone().try_into().unwrap()),
            })
            .collect();
        params.distinguished_name = dev_sidecar_dn(hostname);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = now_offset() - time::Duration::HOUR;
        params.not_after = now_offset() + time::Duration::days(365 * 2);
        params.use_authority_key_identifier_extension = true;

        let cert = params.signed_by(&self.leaf_key, &self.ca_cert, &self.ca_key_pair)?;
        let key_der = PrivateKeyDer::try_from(self.leaf_key.serialize_der())
            .map_err(|e| anyhow::anyhow!("导出临时证书私钥失败: {}", e))?;
        Ok((cert.der().clone(), key_der))
    }
}

/// 读取公共根证书（DER）。
///
/// rustls-native-certs 0.7 只打开 CurrentUser\ROOT，某些 Windows 环境会
/// “拒绝访问”，且拿不到 LocalMachine 的公共根。npm cafile 必须包含公共根，
/// 所以 Windows 下直接枚举本机 ROOT 库，失败再退回 rustls-native-certs。
fn load_public_root_certs() -> Vec<CertificateDer<'static>> {
    #[cfg(windows)]
    {
        match load_windows_store("ROOT", true).or_else(|_| load_windows_store("ROOT", false)) {
            Ok(certs) if !certs.is_empty() => return certs,
            Ok(_) => log_warn!("本机 ROOT 证书库为空，尝试 rustls-native-certs"),
            Err(e) => log_warn!("枚举本机 ROOT 证书库失败: {}", e),
        }
    }
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => certs,
        Err(e) => {
            log_warn!("读取系统根证书失败: {}", e);
            Vec::new()
        }
    }
}

#[cfg(windows)]
fn load_windows_store(
    name: &str,
    local_machine: bool,
) -> Result<Vec<CertificateDer<'static>>, String> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_QUERY_ENCODING_TYPE,
        CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let location = if local_machine {
        CERT_SYSTEM_STORE_LOCAL_MACHINE
    } else {
        CERT_SYSTEM_STORE_CURRENT_USER
    };
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0 as CERT_QUERY_ENCODING_TYPE,
            0,
            location | CERT_STORE_READONLY_FLAG,
            wide.as_ptr() as *const c_void,
        )
    };
    if store.is_null() {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut certs = Vec::new();
    let mut ctx = std::ptr::null();
    loop {
        ctx = unsafe { CertEnumCertificatesInStore(store, ctx) };
        if ctx.is_null() {
            break;
        }
        let encoded = unsafe { (*ctx).pbCertEncoded };
        let len = unsafe { (*ctx).cbCertEncoded } as usize;
        if !encoded.is_null() && len > 0 {
            let der = unsafe { std::slice::from_raw_parts(encoded, len) }.to_vec();
            certs.push(CertificateDer::from(der));
        }
    }
    unsafe { CertCloseStore(store, 0) };
    Ok(certs)
}

/// 生成「系统根证书 + DevSidecar CA」的合并 PEM bundle。
///
/// 用于 npm `cafile`、`SSL_CERT_FILE` 这类**替换**默认信任库的配置项：
/// 若只提供 DevSidecar CA，未走 MITM 的站点（如 registry.npmjs.org）会因
/// 缺少公共根证书而报 `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`。
///
/// bundle 已存在、可解析且不早于 CA 证书时跳过重建，避免每次开启插件的重复开销。
pub fn ensure_ca_bundle(
    ca_cert_path: &std::path::Path,
    bundle_path: &std::path::Path,
) -> Result<()> {
    let ca_pem = std::fs::read(ca_cert_path).map_err(|e| {
        anyhow::anyhow!("读取 DevSidecar CA 失败 {}: {}", ca_cert_path.display(), e)
    })?;
    let ca_certs: Vec<_> =
        rustls_pemfile::certs(&mut ca_pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!ca_certs.is_empty(), "DevSidecar CA 文件中没有证书");

    let bundle_is_valid = || -> bool {
        let Ok(bytes) = std::fs::read(bundle_path) else {
            return false;
        };
        let Ok(certs) = rustls_pemfile::certs(&mut bytes.as_slice()).collect::<Result<Vec<_>, _>>()
        else {
            return false;
        };
        // 至少包含 1 张系统根证书 + DevSidecar CA，且确实包含当前 CA。
        certs.len() >= 2
            && ca_certs
                .iter()
                .all(|ca| certs.iter().any(|c| c.as_ref() == ca.as_ref()))
    };

    if bundle_is_valid() {
        if let (Ok(bundle_meta), Ok(ca_meta)) = (
            std::fs::metadata(bundle_path),
            std::fs::metadata(ca_cert_path),
        ) {
            let newer_than_ca = bundle_meta
                .modified()
                .ok()
                .zip(ca_meta.modified().ok())
                .is_some_and(|(b, c)| b >= c);
            // 系统根证书库会随 Windows 更新增删，而 cafile / SSL_CERT_FILE 是
            // “替换”语义：长期复用旧 bundle 会让新根证书缺失。超过 7 天即重建。
            let recent = bundle_meta
                .modified()
                .ok()
                .and_then(|t| std::time::SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age < std::time::Duration::from_secs(7 * 24 * 3600));
            if newer_than_ca && recent {
                return Ok(());
            }
        }
    }

    let mut out = String::from_utf8_lossy(&ca_pem).to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }

    let public_roots = load_public_root_certs();
    let mut count = 0usize;
    {
        use base64::Engine;
        for cert in &public_roots {
            let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
            out.push_str("-----BEGIN CERTIFICATE-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(chunk)?);
                out.push('\n');
            }
            out.push_str("-----END CERTIFICATE-----\n");
            count += 1;
        }
    }
    anyhow::ensure!(
        count > 0,
        "系统根证书为空，无法生成 CA bundle；npm cafile 需要公共根证书",
    );

    if let Some(parent) = bundle_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 原子替换：npm / Node 可能在写入过程中并发读取 cafile，不能暴露半截 PEM。
    let tmp = bundle_path.with_extension("crt.tmp");
    std::fs::write(&tmp, &out)?;
    if let Err(first) = std::fs::rename(&tmp, bundle_path) {
        std::fs::write(bundle_path, &out).map_err(|second| {
            let _ = std::fs::remove_file(&tmp);
            anyhow::anyhow!(
                "写入 CA bundle 失败 {}: rename={} overwrite={}",
                bundle_path.display(),
                first,
                second
            )
        })?;
        let _ = std::fs::remove_file(&tmp);
    }

    // 解析回读，确认合并后的 bundle 同时包含公共根和当前 DevSidecar CA。
    anyhow::ensure!(bundle_is_valid(), "CA bundle 写入后校验失败");
    log_info!(
        "已生成合并 CA bundle（{} 张系统根证书 + DevSidecar CA）: {}",
        count,
        bundle_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod ca_bundle_tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        // 测试环境里 TEMP 可能指向不可写的 C:	mp，统一落在仓库 target 下。
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tmp")
            .join(format!(
                "dev-sidecar-tls-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn parse_count(path: &std::path::Path) -> usize {
        let bytes = std::fs::read(path).unwrap();
        rustls_pemfile::certs(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len()
    }

    #[test]
    fn merged_bundle_keeps_public_roots_and_app_ca() {
        let dir = temp_dir("bundle");
        let cert = dir.join("root.crt");
        let key = dir.join("root.key");
        let bundle = dir.join("ca-bundle.crt");
        CertificateAuthority::init(&cert, &key, 8).unwrap();

        ensure_ca_bundle(&cert, &bundle).unwrap();
        let first = parse_count(&bundle);
        assert!(first >= 2, "bundle 必须同时包含公共根和 DevSidecar CA");

        // 仅含本应用 CA 的历史残留必须被判为无效并重建，而不是因文件较大被复用。
        std::fs::copy(&cert, &bundle).unwrap();
        ensure_ca_bundle(&cert, &bundle).unwrap();
        assert_eq!(parse_count(&bundle), first);

        // 幂等：有效且不早于 CA 的 bundle 不重复重写。
        let before = std::fs::metadata(&bundle).unwrap().modified().unwrap();
        ensure_ca_bundle(&cert, &bundle).unwrap();
        assert_eq!(
            std::fs::metadata(&bundle).unwrap().modified().unwrap(),
            before
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
