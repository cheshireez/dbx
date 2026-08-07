//! 与 dbx-web 的 `waf_codec` 保持一致的 AES-256-GCM 载荷加密。
//!
//! dbx-web 后端已对 `dbx1:` 前缀的 SQL 载荷做无条件解密,因此这里只需要
//! "加密"一侧:当环境变量 `DBX_MCP_WAF_SQL_ENCODE=1` 时,查询接口请求体中的
//! `sql` 字段会被加密后再发送,避免内容型 WAF 按 SQL 关键字误拦。
//! 密钥来自 `DBX_WAF_SQL_KEY`(SHA-256 派生 32 字节),缺省与 dbx-web 相同。
//!
//! 注意:密钥随二进制分发,本模块只用于绕过内容检测,不提供面向真实攻击者的保密性。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

const WAF_PREFIX: &str = "dbx1:";
const DEFAULT_WAF_KEY: &str = "dbx-waf-default-key-2026";
const NONCE_LEN: usize = 12;

fn waf_key() -> [u8; 32] {
    let secret = std::env::var("DBX_WAF_SQL_KEY").unwrap_or_else(|_| DEFAULT_WAF_KEY.to_string());
    Sha256::digest(secret.as_bytes()).into()
}

fn encode_sql(sql: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(&waf_key()).map_err(|_| "waf key init failed".to_string())?;
    let nonce_bytes = uuid::Uuid::new_v4().as_bytes()[..NONCE_LEN].to_vec();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, sql.as_bytes()).map_err(|_| "waf sql encrypt failed".to_string())?;
    let mut raw = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ciphertext);
    Ok(format!("{WAF_PREFIX}{}", BASE64.encode(raw)))
}

/// 仅在 `DBX_MCP_WAF_SQL_ENCODE=1` 时加密,否则原样返回(保持默认行为不变)。
pub fn maybe_encode_sql(sql: &str) -> String {
    let enabled = std::env::var("DBX_MCP_WAF_SQL_ENCODE").map(|value| value == "1").unwrap_or(false);
    if enabled {
        encode_sql(sql).unwrap_or_else(|_| sql.to_string())
    } else {
        sql.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_sql(value: &str) -> Result<String, String> {
        let payload = value.strip_prefix(WAF_PREFIX).ok_or_else(|| "missing prefix".to_string())?;
        let raw = BASE64.decode(payload).map_err(|_| "invalid base64".to_string())?;
        if raw.len() < NONCE_LEN + 16 {
            return Err("payload too short".to_string());
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&waf_key()).map_err(|_| "key init failed".to_string())?;
        let plain = cipher.decrypt(Nonce::from_slice(nonce), ciphertext).map_err(|_| "decrypt failed".to_string())?;
        String::from_utf8(plain).map_err(|_| "not utf-8".to_string())
    }

    #[test]
    fn encoded_payload_round_trips_and_hides_keywords() {
        let sql = "SELECT * FROM users WHERE id = 1;";
        let encoded = encode_sql(sql).unwrap();
        assert!(encoded.starts_with(WAF_PREFIX));
        assert!(!encoded.contains("SELECT"));
        assert_eq!(decode_sql(&encoded).unwrap(), sql);
    }

    #[test]
    fn encoding_follows_env_flag() {
        let sql = "SELECT * FROM t";
        std::env::set_var("DBX_MCP_WAF_SQL_ENCODE", "1");
        let encoded = maybe_encode_sql(sql);
        assert!(encoded.starts_with(WAF_PREFIX));
        assert_eq!(decode_sql(&encoded).unwrap(), sql);
        std::env::set_var("DBX_MCP_WAF_SQL_ENCODE", "0");
        assert_eq!(maybe_encode_sql(sql), sql);
        std::env::remove_var("DBX_MCP_WAF_SQL_ENCODE");
    }
}
