//! 可选传输层 SQL 载荷加密(用于绕过内容型 WAF 的误拦)。
//!
//! ## 格式(v2,当前)
//! 密文无固定前缀,外观与普通随机 token 无异:
//! `base64( nonce[12] || masked_magic[4] || ciphertext || tag[16] )`,
//! 其中 `masked_magic = "DBX1" XOR SHA256(key || nonce)[0..4]`。
//! 识别凭混淆 magic(只有密钥持有者能算出),传输中不出现任何固定明文特征
//! (无 `dbx1:` 前缀、无明文 magic),避免被按签名/固定模式拦截。
//! magic 匹配但 GCM 解密失败视为篡改,返回 400;mismatch 一律按明文透传。
//!
//! ## 兼容(v1,旧格式)
//! 仍接受 `dbx1:<base64(nonce[12] || ciphertext || tag[16])>` 旧格式
//! (n8n 工作流等旧客户端在用),语义保持严格。
//!
//! 密钥来自环境变量 `DBX_WAF_SQL_KEY`(经 SHA-256 派生为 32 字节),缺省用内置默认值,
//! 该默认值与前端构建期 `VITE_DBX_WAF_SQL_KEY` 保持一致。
//!
//! 注意:密钥会随前端 JS 一起下发,本模块只用于让 WAF 无法直接识别 SQL 文本,
//! 不提供面向真实攻击者的保密性。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::AppError;

const WAF_PREFIX: &str = "dbx1:";
const DEFAULT_WAF_KEY: &str = "dbx-waf-default-key-2026";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// v2 内嵌混淆 magic(不以明文出现在传输中)。
const MAGIC: [u8; 4] = *b"DBX1";
const MAGIC_LEN: usize = MAGIC.len();

fn waf_key() -> [u8; 32] {
    let secret = std::env::var("DBX_WAF_SQL_KEY").unwrap_or_else(|_| DEFAULT_WAF_KEY.to_string());
    Sha256::digest(secret.as_bytes()).into()
}

/// 计算 v2 混淆 magic:magic XOR SHA256(key || nonce)[0..4]。
/// 输入 nonce(12 字节);输出随 nonce 伪随机变化的 4 字节识别码。
fn masked_magic(nonce: &[u8]) -> [u8; MAGIC_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(waf_key());
    hasher.update(nonce);
    let digest = hasher.finalize();
    let mut masked = MAGIC;
    for (index, byte) in masked.iter_mut().enumerate() {
        *byte ^= digest[index];
    }
    masked
}

fn decrypt_parts(nonce: &[u8], ciphertext: &[u8]) -> Result<String, AppError> {
    if nonce.len() != NONCE_LEN || ciphertext.len() < TAG_LEN {
        return Err(AppError::bad_request("invalid waf-encoded sql payload (too short)"));
    }
    let cipher = Aes256Gcm::new_from_slice(&waf_key()).map_err(|_| AppError::internal("waf key init failed"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| AppError::bad_request("waf-encoded sql decrypt failed"))?;
    String::from_utf8(plain).map_err(|_| AppError::bad_request("waf-encoded sql is not valid utf-8"))
}

/// 内部解码:Ok(None)=明文透传;Ok(Some(_))=解密成功;Err=密文损坏/篡改。
fn decode_sql_inner(value: &str) -> Result<Option<String>, AppError> {
    // v1 旧格式(显式前缀,严格语义)
    if let Some(payload) = value.strip_prefix(WAF_PREFIX) {
        let raw =
            BASE64.decode(payload).map_err(|_| AppError::bad_request("invalid waf-encoded sql payload (base64)"))?;
        if raw.len() < NONCE_LEN + TAG_LEN {
            return Err(AppError::bad_request("invalid waf-encoded sql payload (too short)"));
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        return decrypt_parts(nonce, ciphertext).map(Some);
    }
    // v2 无前缀格式:凭混淆 magic 识别;不像密文就当明文
    let Ok(raw) = BASE64.decode(value) else {
        return Ok(None);
    };
    if raw.len() < NONCE_LEN + MAGIC_LEN + TAG_LEN + 1 {
        return Ok(None);
    }
    let (nonce, rest) = raw.split_at(NONCE_LEN);
    let (masked, ciphertext) = rest.split_at(MAGIC_LEN);
    if masked != masked_magic(nonce) {
        return Ok(None);
    }
    // magic 匹配即认定为密文:解密失败按篡改拒绝
    decrypt_parts(nonce, ciphertext).map(Some)
}

/// 解码 SQL 载荷:自动识别 v2(无前缀)与 v1(`dbx1:` 前缀)密文;
/// 非密文原样返回(兼容明文请求)。密文损坏时返回错误(篡改拒绝)。
pub fn decode_sql(value: &str) -> Result<String, AppError> {
    Ok(decode_sql_inner(value)?.unwrap_or_else(|| value.to_string()))
}

/// 批量解码(execute-batch / execute-in-transaction / execute-script-2pc 使用)。
pub fn decode_sql_vec(values: Vec<String>) -> Result<Vec<String>, AppError> {
    values.into_iter().map(|value| decode_sql(&value)).collect()
}

/// 递归解码 JSON 中所有密文字符串(v2 无前缀 / v1 `dbx1:` 前缀;build-* options、
/// AI 消息、导出过滤等任意嵌套结构使用,避免逐字段样板)。
/// 采用尽力解码语义:解不出的(业务数据恰好像密文)原样保留,不报错——
/// 本方案只做防内容检测,不承担完整性校验。
/// 通过 `changed` 报告是否真的解出了密文(请求体中间件据此决定透传原字节还是重写)。
fn decode_sql_in_json(value: serde_json::Value, changed: &mut bool) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => match decode_sql_inner(&text) {
            Ok(Some(decoded)) => {
                *changed = true;
                serde_json::Value::String(decoded)
            }
            _ => serde_json::Value::String(text),
        },
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(|item| decode_sql_in_json(item, changed)).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter().map(|(key, item)| (key, decode_sql_in_json(item, changed))).collect(),
        ),
        other => other,
    }
}

/// 解析请求体上界:与 `web_body_limit_bytes()` 默认值(1GB)一致。
/// 仅 JSON 请求体被缓冲;multipart 等非 JSON 内容类型直接跳过。
const DECODE_BODY_LIMIT_BYTES: usize = 1024 * 1024 * 1024;

/// axum 中间件:对 `application/json` 请求体整体递归解码密文字符串,
/// 让所有接口(含嵌套 options / 动态键消息)统一获得密文还原能力。
/// 未解出任何密文时原样透传,不改变字节与 Content-Length。
pub async fn decode_json_request_body(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let is_json = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        .unwrap_or(false);
    if !is_json {
        return next.run(req).await;
    }
    let (mut parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, DECODE_BODY_LIMIT_BYTES).await {
        Ok(body) => body,
        Err(error) => return AppError::bad_request(format!("invalid request body: {error}")).into_response(),
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        // 非合法 JSON 原样透传,交由既有 Json 提取器报错,行为与改造前一致
        return next.run(axum::http::Request::from_parts(parts, axum::body::Body::from(body))).await;
    };
    let mut changed = false;
    let decoded_value = decode_sql_in_json(value, &mut changed);
    if !changed {
        // 请求体不含密文:原样透传,保持请求字节不变
        return next.run(axum::http::Request::from_parts(parts, axum::body::Body::from(body))).await;
    }
    let decoded = match serde_json::to_vec(&decoded_value) {
        Ok(decoded) => decoded,
        Err(error) => return AppError::internal(format!("waf payload re-encode failed: {error}")).into_response(),
    };
    if let Ok(length) = decoded.len().to_string().parse::<axum::http::HeaderValue>() {
        parts.headers.insert(axum::http::header::CONTENT_LENGTH, length);
    }
    next.run(axum::http::Request::from_parts(parts, axum::body::Body::from(decoded))).await
}

/// 测试辅助:构造 v1 旧格式密文(`dbx1:` 前缀),供其他模块单测复用。
#[cfg(test)]
pub(crate) fn encode_sql_for_test(plain: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(&waf_key()).unwrap();
    let nonce_bytes = uuid::Uuid::new_v4().as_bytes()[..NONCE_LEN].to_vec();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plain.as_bytes()).unwrap();
    let mut raw = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ciphertext);
    format!("{WAF_PREFIX}{}", BASE64.encode(raw))
}

/// 测试辅助:构造 v2 无前缀密文(与前端 encodeSql 现行输出同格式)。
#[cfg(test)]
pub(crate) fn encode_sql_v2_for_test(plain: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(&waf_key()).unwrap();
    let nonce_bytes = uuid::Uuid::new_v4().as_bytes()[..NONCE_LEN].to_vec();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plain.as_bytes()).unwrap();
    let mut raw = Vec::with_capacity(NONCE_LEN + MAGIC_LEN + ciphertext.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&masked_magic(&nonce_bytes));
    raw.extend_from_slice(&ciphertext);
    BASE64.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_for_test(plain: &str) -> String {
        encode_sql_for_test(plain)
    }

    #[test]
    fn round_trip_encodes_and_decodes() {
        let sql = "SELECT * FROM users WHERE id = 1;";
        let encoded = encode_for_test(sql);
        assert!(encoded.starts_with(WAF_PREFIX));
        assert_eq!(decode_sql(&encoded).unwrap(), sql);
        // 密文中不应出现明文关键字
        assert!(!encoded.contains("SELECT"));
    }

    #[test]
    fn v2_round_trip_hides_all_fixed_markers() {
        let sql = "SELECT * FROM users WHERE id = 1;";
        let encoded = encode_sql_v2_for_test(sql);
        // 无前缀、无明文 magic、无 SQL 关键字——不出现任何固定明文特征
        assert!(!encoded.contains("dbx1"));
        assert!(!encoded.contains("DBX1"));
        assert!(!encoded.contains("SELECT"));
        assert!(!encoded.contains(':'));
        assert_eq!(decode_sql(&encoded).unwrap(), sql);
        // magic 随 nonce 变化:同一明文两次编码外观不同
        assert_ne!(encode_sql_v2_for_test(sql), encoded);
    }

    #[test]
    fn v2_tampered_payload_is_rejected_but_plain_text_passes() {
        let encoded = encode_sql_v2_for_test("SELECT 1");
        let mut bytes = BASE64.decode(&encoded).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // 篡改密文/magic保持不变
        let tampered = BASE64.encode(bytes);
        assert!(decode_sql(&tampered).is_err());
        // 恰好像是合法 base64 长串的业务数据(magic 不匹配)按明文透传
        assert_eq!(
            decode_sql("dGhpcyBpcyBhIHBsYWluIHRva2VuIGRhdGEgYmFzZTY0").unwrap(),
            "dGhpcyBpcyBhIHBsYWluIHRva2VuIGRhdGEgYmFzZTY0"
        );
    }

    #[test]
    fn v2_golden_sample_from_n8n_js_implementation() {
        // 由 scripts/js_encrypt_sql.txt(n8n 手写 JS 加密实现)在默认密钥下产出的固定样本。
        // 跨实现互通的黄金锚点:前端(WebCrypto)/后端(Rust)/n8n(手写 JS)三端格式一致。
        let golden =
            "PAIn0kzrrOZVqcXcsaIaGinqETBpniVrKEDClsf13wbEzghUaVM+3FUnhtFPgoaZ92ggbJdNPwz8h6gripyQ4sbjeIdjOZE9sQ==";
        assert_eq!(decode_sql(golden).unwrap(), "SELECT * FROM users WHERE name='admin' --");
    }

    #[test]
    fn vec_decode_mixes_v1_v2_and_plain() {
        let values = vec![
            encode_for_test("DELETE FROM t"),
            encode_sql_v2_for_test("UPDATE t SET c = 1"),
            "SELECT 2".to_string(),
        ];
        let decoded = decode_sql_vec(values).unwrap();
        assert_eq!(
            decoded,
            vec!["DELETE FROM t".to_string(), "UPDATE t SET c = 1".to_string(), "SELECT 2".to_string()]
        );
    }

    #[test]
    fn plain_sql_passes_through() {
        assert_eq!(decode_sql("SELECT 1").unwrap(), "SELECT 1");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let encoded = encode_for_test("SELECT 1");
        let mut bytes = BASE64.decode(encoded.trim_start_matches(WAF_PREFIX)).unwrap();
        bytes[NONCE_LEN] ^= 0x01;
        let tampered = format!("{WAF_PREFIX}{}", BASE64.encode(bytes));
        assert!(decode_sql(&tampered).is_err());
    }

    #[test]
    fn json_recursive_decode_covers_nested_fields() {
        let value: serde_json::Value = serde_json::json!({
            "options": { "originalSql": encode_for_test("SELECT 1"), "limit": 10 },
            "statements": [encode_for_test("DELETE FROM t"), encode_sql_v2_for_test("UPDATE t SET c = 1"), "plain text"],
            "flag": true,
        });
        let mut changed = false;
        let decoded = decode_sql_in_json(value, &mut changed);
        assert!(changed);
        assert_eq!(decoded["options"]["originalSql"], "SELECT 1");
        assert_eq!(decoded["statements"][0], "DELETE FROM t");
        assert_eq!(decoded["statements"][1], "UPDATE t SET c = 1");
        // 明文与非字符串值原样保留
        assert_eq!(decoded["statements"][2], "plain text");
        assert_eq!(decoded["flag"], true);
    }

    #[test]
    fn json_decode_keeps_business_data_with_dbx1_prefix() {
        // 业务数据恰好以 dbx1: 开头但解不出密文时,原样保留(尽力解码语义)
        let value = serde_json::json!({ "cell": "dbx1:not-valid-ciphertext" });
        let mut changed = false;
        let decoded = decode_sql_in_json(value, &mut changed);
        assert!(!changed);
        assert_eq!(decoded["cell"], "dbx1:not-valid-ciphertext");
    }
}
