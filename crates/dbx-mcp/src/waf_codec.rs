//! 与 dbx-web 的 `waf_codec` 保持一致的 AES-256-GCM 载荷加密(v2 无前缀格式)。
//!
//! dbx-web 后端已对密文载荷做无条件解密,因此这里只需要"加密"一侧:
//! 当环境变量 `DBX_MCP_WAF_SQL_ENCODE=1` 时,查询接口请求体中的 `sql` 字段
//! 会被加密后再发送,避免内容型 WAF 按 SQL 关键字误拦。
//! 密钥来自 `DBX_WAF_SQL_KEY`(SHA-256 派生 32 字节),缺省与 dbx-web 相同。
//!
//! v2 格式:`base64(nonce[12] || masked_magic[4] || ciphertext || tag[16])`,
//! `masked_magic = "DBX1" XOR SHA256(key || nonce)[0..4]`——无固定前缀,
//! 外观与随机 token 无异,识别凭混淆 magic(只有密钥持有者能算出)。
//!
//! 注意:密钥随二进制分发,本模块只用于绕过内容检测,不提供面向真实攻击者的保密性。

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

const DEFAULT_WAF_KEY: &str = "dbx-waf-default-key-2026";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// v2 内嵌混淆 magic(不以明文出现在传输中)。
const MAGIC: [u8; 4] = *b"DBX1";
const MAGIC_LEN: usize = MAGIC.len();

/// 深度加密时视为承载 SQL/查询文本的命名段(与前端 http.ts 的
/// `WAF_SQL_FIELD_TOKENS` 保持一致,改一处需同步另一处)。
const WAF_SQL_FIELD_TOKENS: &[&str] = &[
    "sql",
    "statement",
    "where",
    "query",
    "filter",
    "sort",
    "order",
    "group",
    "having",
    "join",
    "condition",
    "predicate",
    "expression",
    "clause",
    "term",
    "script",
    "command",
    "pipeline",
    "projection",
    "message",
    "content",
    "text",
    "input",
    "search",
    "pattern",
    "definition",
    "document",
    "body",
    "ddl",
    // 任意文本载荷:Redis/KV 写入值、单元格值、导出行数据等(可能承载 SQL 文本)
    "value",
    "values",
    "rows",
];

fn waf_key() -> [u8; 32] {
    let secret = std::env::var("DBX_WAF_SQL_KEY").unwrap_or_else(|_| DEFAULT_WAF_KEY.to_string());
    Sha256::digest(secret.as_bytes()).into()
}

/// 计算 v2 混淆 magic:magic XOR SHA256(key || nonce)[0..4]。
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

fn encode_sql(sql: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(&waf_key()).map_err(|_| "waf key init failed".to_string())?;
    let nonce_bytes = uuid::Uuid::new_v4().as_bytes()[..NONCE_LEN].to_vec();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, sql.as_bytes()).map_err(|_| "waf sql encrypt failed".to_string())?;
    let mut raw = Vec::with_capacity(NONCE_LEN + MAGIC_LEN + ciphertext.len());
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&masked_magic(&nonce_bytes));
    raw.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(raw))
}

/// 判断字符串是否已是密文(v2 混淆 magic 匹配或旧 `dbx1:` 前缀;幂等加密用)。
pub fn is_waf_encoded(value: &str) -> bool {
    if value.starts_with("dbx1:") {
        return true;
    }
    let Ok(raw) = BASE64.decode(value) else {
        return false;
    };
    if raw.len() < NONCE_LEN + MAGIC_LEN + TAG_LEN + 1 {
        return false;
    }
    let (nonce, rest) = raw.split_at(NONCE_LEN);
    let (masked, _) = rest.split_at(MAGIC_LEN);
    masked == masked_magic(nonce)
}

/// 加密一条文本(内部):幂等,已加密字符串原样返回,避免深度加密与逐字段
/// 加密(如查询接口显式加密的 `sql`)叠加成双层密文。
fn encode_text_once(text: &str) -> String {
    if is_waf_encoded(text) {
        return text.to_string();
    }
    encode_sql(text).unwrap_or_else(|_| text.to_string())
}

/// 仅在 `DBX_MCP_WAF_SQL_ENCODE=1` 时加密,否则原样返回(保持默认行为不变)。
pub fn maybe_encode_sql(sql: &str) -> String {
    let enabled = std::env::var("DBX_MCP_WAF_SQL_ENCODE").map(|value| value == "1").unwrap_or(false);
    if enabled {
        encode_text_once(sql)
    } else {
        sql.to_string()
    }
}

/// 把字段名拆分为命名段(驼峰/下划线边界,小写),如 whereInput -> ["where","input"]。
fn field_tokens(name: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            let is_upper = ch.is_ascii_uppercase();
            if is_upper && prev_lower && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            current.push(ch.to_ascii_lowercase());
            prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            prev_lower = false;
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// 判断单个命名段是否承载 SQL/查询文本(含简单单复数归一,如 filters -> filter)。
fn is_waf_sql_token(token: &str) -> bool {
    if WAF_SQL_FIELD_TOKENS.contains(&token) {
        return true;
    }
    token.len() > 3 && token.ends_with('s') && WAF_SQL_FIELD_TOKENS.contains(&&token[..token.len() - 1])
}

/// 判断 JSON 字段名是否承载 SQL 文本(与前端 http.ts `isWafSqlField` 规则一致)。
pub fn is_waf_sql_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with("sql") || lower.ends_with("json") {
        return true;
    }
    field_tokens(name).iter().any(|token| is_waf_sql_token(token))
}

/// 递归加密 JSON 中命中字段名的字符串(与前端 encodeSqlDeep 规则一致):
/// 命中字段名的对象/数组子树整体加密(覆盖 tableFilters 类动态键映射),
/// 对象键名不参与加密;已加密字符串原样保留(幂等)。
/// `matched` 表示当前值所属字段名已命中(或父级已命中),其下所有字符串强制加密。
fn encode_json_value_inner(value: &serde_json::Value, matched: bool) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => {
            serde_json::Value::String(if matched { encode_text_once(text) } else { text.clone() })
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(|item| encode_json_value_inner(item, matched)).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, item)| {
                    let child_matched = matched || is_waf_sql_field(key);
                    (key.clone(), encode_json_value_inner(item, child_matched))
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// 对外入口:按环境变量开关对请求体 JSON 做深度加密(关闭时原样返回)。
pub fn encode_json_value(value: serde_json::Value) -> serde_json::Value {
    let enabled = std::env::var("DBX_MCP_WAF_SQL_ENCODE").map(|flag| flag == "1").unwrap_or(false);
    if !enabled {
        return value;
    }
    encode_json_value_inner(&value, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_sql(value: &str) -> Result<String, String> {
        let raw = BASE64.decode(value).map_err(|_| "invalid base64".to_string())?;
        if raw.len() < NONCE_LEN + MAGIC_LEN + TAG_LEN + 1 {
            return Err("payload too short".to_string());
        }
        let (nonce, rest) = raw.split_at(NONCE_LEN);
        let (masked, ciphertext) = rest.split_at(MAGIC_LEN);
        if masked != masked_magic(nonce) {
            return Err("magic mismatch".to_string());
        }
        let cipher = Aes256Gcm::new_from_slice(&waf_key()).map_err(|_| "key init failed".to_string())?;
        let plain = cipher.decrypt(Nonce::from_slice(nonce), ciphertext).map_err(|_| "decrypt failed".to_string())?;
        String::from_utf8(plain).map_err(|_| "not utf-8".to_string())
    }

    #[test]
    fn encoded_payload_round_trips_and_hides_keywords() {
        let sql = "SELECT * FROM users WHERE id = 1;";
        let encoded = encode_sql(sql).unwrap();
        // v2 无前缀:不出现任何固定明文特征
        assert!(!encoded.contains("dbx1"));
        assert!(!encoded.contains("DBX1"));
        assert!(!encoded.contains("SELECT"));
        assert!(!encoded.contains(':'));
        assert_eq!(decode_sql(&encoded).unwrap(), sql);
        // magic 随 nonce 变化:同一明文两次编码外观不同
        assert_ne!(encode_sql(sql).unwrap(), encoded);
    }

    #[test]
    fn encoding_follows_env_flag() {
        let sql = "SELECT * FROM t";
        std::env::set_var("DBX_MCP_WAF_SQL_ENCODE", "1");
        let encoded = maybe_encode_sql(sql);
        assert_eq!(decode_sql(&encoded).unwrap(), sql);
        std::env::set_var("DBX_MCP_WAF_SQL_ENCODE", "0");
        assert_eq!(maybe_encode_sql(sql), sql);
        std::env::remove_var("DBX_MCP_WAF_SQL_ENCODE");
    }

    #[test]
    fn field_names_match_like_frontend() {
        // 复合命名(驼峰/下划线)与单复数均命中,与前端 isWafSqlField 口径一致
        assert!(is_waf_sql_field("whereInput"));
        assert!(is_waf_sql_field("orderBy"));
        assert!(is_waf_sql_field("tableFilters"));
        assert!(is_waf_sql_field("searchText"));
        assert!(is_waf_sql_field("originalSql"));
        assert!(is_waf_sql_field("filterJson"));
        assert!(is_waf_sql_field("command"));
        assert!(is_waf_sql_field("messages"));
        // 任意文本载荷(单元格值 / 导出行数据 / Redis-KV 写入值)
        assert!(is_waf_sql_field("value"));
        assert!(is_waf_sql_field("values"));
        assert!(is_waf_sql_field("rows"));
        assert!(is_waf_sql_field("newRows"));
        assert!(is_waf_sql_field("rawValue"));
        assert!(is_waf_sql_field("ddl"));
        assert!(is_waf_sql_field("targetDdl"));
        // 标识符/时间戳类字段不命中,避免无谓密文化
        assert!(!is_waf_sql_field("updateTime"));
        assert!(!is_waf_sql_field("columns"));
        assert!(!is_waf_sql_field("tableName"));
    }

    #[test]
    fn deep_encode_covers_dynamic_key_maps_and_stays_idempotent() {
        let value = serde_json::json!({
            "options": {
                "whereInput": "push_status = 2 AND warning_source = 'x'",
                "orderBy": "\"id\" DESC",
                "tableName": "warning_info",
                "limit": 500,
            },
            "tableFilters": { "t_order": "id <= 90000" },
        });
        let encoded = encode_json_value_inner(&value, false);
        // 命中字段不再出现 SQL 特征,且可解密还原
        let where_input = encoded["options"]["whereInput"].as_str().unwrap();
        assert!(!where_input.contains("AND"));
        assert_eq!(decode_sql(where_input).unwrap(), "push_status = 2 AND warning_source = 'x'");
        assert_eq!(decode_sql(encoded["options"]["orderBy"].as_str().unwrap()).unwrap(), "\"id\" DESC");
        // 动态键映射(tableFilters):键保持明文,值加密
        assert_eq!(encoded["tableFilters"]["t_order"].is_string(), true);
        assert_eq!(decode_sql(encoded["tableFilters"]["t_order"].as_str().unwrap()).unwrap(), "id <= 90000");
        // 非命中字段保持明文
        assert_eq!(encoded["options"]["tableName"], "warning_info");
        assert_eq!(encoded["options"]["limit"], 500);
        // 幂等:对已加密结果二次编码不发生变化
        assert_eq!(encode_json_value_inner(&encoded, false), encoded);
    }
}
