//! 可选传输层 SQL 载荷加密(用于绕过内容型 WAF 的误拦)。
//!
//! 前后端约定:请求中的 `sql` / `statements` 若以 `dbx1:` 开头,视为
//! AES-256-GCM 加密载荷,格式为 `dbx1:<base64(nonce[12] || ciphertext || tag[16])>`。
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

fn waf_key() -> [u8; 32] {
    let secret = std::env::var("DBX_WAF_SQL_KEY").unwrap_or_else(|_| DEFAULT_WAF_KEY.to_string());
    Sha256::digest(secret.as_bytes()).into()
}

/// 若 `value` 带 `dbx1:` 前缀则解密,否则原样返回(兼容明文请求)。
pub fn decode_sql(value: &str) -> Result<String, AppError> {
    let Some(payload) = value.strip_prefix(WAF_PREFIX) else {
        return Ok(value.to_string());
    };
    let raw = BASE64.decode(payload).map_err(|_| AppError::bad_request("invalid waf-encoded sql payload (base64)"))?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        return Err(AppError::bad_request("invalid waf-encoded sql payload (too short)"));
    }
    let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(&waf_key()).map_err(|_| AppError::internal("waf key init failed"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| AppError::bad_request("waf-encoded sql decrypt failed"))?;
    String::from_utf8(plain).map_err(|_| AppError::bad_request("waf-encoded sql is not valid utf-8"))
}

/// 批量解码(execute-batch / execute-in-transaction / execute-script-2pc 使用)。
pub fn decode_sql_vec(values: Vec<String>) -> Result<Vec<String>, AppError> {
    values.into_iter().map(|value| decode_sql(&value)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_for_test(plain: &str) -> String {
        let cipher = Aes256Gcm::new_from_slice(&waf_key()).unwrap();
        let nonce_bytes = uuid::Uuid::new_v4().as_bytes()[..NONCE_LEN].to_vec();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plain.as_bytes()).unwrap();
        let mut raw = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        raw.extend_from_slice(&nonce_bytes);
        raw.extend_from_slice(&ciphertext);
        format!("{WAF_PREFIX}{}", BASE64.encode(raw))
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
}
