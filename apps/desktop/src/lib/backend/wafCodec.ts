// ---------------------------------------------------------------------------
// 可选传输层载荷加密(绕过内容型 WAF 对 SQL 关键字的误拦)
// 仅在构建时设置 VITE_DBX_WAF_SQL_ENCODE=1 才启用;后端 waf_codec 负责解密,
// 密钥需与后端 DBX_WAF_SQL_KEY 保持一致(缺省用同一内置默认值)。
// v2 格式:base64(nonce[12] || masked_magic[4] || cipher(含 tag)),无固定前缀,
// masked_magic = "DBX1" XOR SHA256(key || nonce)[0..4],外观与随机 token 无异,
// 传输中不出现任何固定明文特征;旧 `dbx1:` 前缀格式仅作识别兼容(后端仍接受)。
//
// 独立成模块的原因:http.ts 与 mq-http.ts 都需要请求体加密,而 http.ts 又
// `export * from mq-http`,放在 http.ts 会形成循环依赖。
// ---------------------------------------------------------------------------
const WAF_SQL_ENCODE_FLAG = "VITE_DBX_WAF_SQL_ENCODE";
const WAF_SQL_KEY = import.meta.env.VITE_DBX_WAF_SQL_KEY || "dbx-waf-default-key-2026";
const WAF_SQL_PREFIX = "dbx1:";
const WAF_MAGIC = [0x44, 0x42, 0x58, 0x31]; // "DBX1",经混淆后才出现在传输中

/**
 * 判断构建期加密开关是否启用(每次读取,便于测试注入环境变量)。
 * 输入:无;输出:true 表示请求体需要做 WAF 载荷加密。
 */
function isWafEncodeEnabled(): boolean {
  return import.meta.env[WAF_SQL_ENCODE_FLAG] === "1";
}

// 深度加密时视为承载 SQL/查询文本的命名段(统一小写比较):
// 命中规则:字段名 xxSql / xxJson 后缀,或字段名拆分出的任一命名段在名单内
// (支持驼峰/下划线复合名与单复数,如 whereInput -> where+input、orderBy -> order+by、
// tableFilters -> filter、searchText -> text),用于覆盖 whereInput / orderBy /
// searchText / tableFilters 等非标准命名的 SQL 片段字段。
const WAF_SQL_FIELD_TOKENS = new Set([
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
]);

/**
 * 把字段名拆分为命名段(驼峰/下划线/短横线边界),全部转小写。
 * 输入:字段名(如 whereInput / table_filters);输出:命名段数组(如 ["where","input"])。
 */
function wafFieldTokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((token) => token.toLowerCase());
}

/**
 * 判断单个命名段是否承载 SQL/查询文本(含简单单复数归一,如 filters -> filter)。
 * 输入:小写命名段;输出:true 表示命中关键词名单。
 */
function isWafSqlToken(token: string): boolean {
  if (WAF_SQL_FIELD_TOKENS.has(token)) return true;
  return token.length > 3 && token.endsWith("s") && WAF_SQL_FIELD_TOKENS.has(token.slice(0, -1));
}

/**
 * 判断 JSON 字段名是否承载 SQL 文本(用于深度加密遍历)。
 * 输入:字段名(任意大小写);输出:true 表示该字段下的字符串需要加密。
 */
export function isWafSqlField(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower.endsWith("sql") || lower.endsWith("json")) return true;
  return wafFieldTokens(name).some(isWafSqlToken);
}

// 派生密钥缓存:每个请求只做一次 SHA-256 + importKey,避免深度加密时重复开销。
// keyBytes 保留原始字节,供 masked_magic 派生(加密与幂等识别共用)。
let wafKeyMaterial: Promise<{ key: CryptoKey; keyBytes: Uint8Array }> | null = null;

/**
 * 派生并缓存 AES-GCM 加密密钥(SHA-256(口令) -> 32 字节)。
 * 输入:无(读取构建期 WAF_SQL_KEY);输出:可加密的 CryptoKey 与原始密钥字节。
 * 注意:只在 secure context(HTTPS)下可用,失败由调用方退回明文。
 */
function wafImportKey(): Promise<{ key: CryptoKey; keyBytes: Uint8Array }> {
  if (!wafKeyMaterial) {
    wafKeyMaterial = (async () => {
      const enc = new TextEncoder();
      const keyBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(WAF_SQL_KEY)));
      const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
      return { key, keyBytes };
    })();
  }
  return wafKeyMaterial;
}

/**
 * 计算 v2 混淆 magic:magic XOR SHA256(key || nonce)[0..4]。
 * 输入:密钥原始字节与 12 字节 nonce;输出随 nonce 伪随机变化的 4 字节识别码。
 */
async function wafMaskedMagic(keyBytes: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(keyBytes.length + nonce.length);
  input.set(keyBytes, 0);
  input.set(nonce, keyBytes.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  return new Uint8Array(WAF_MAGIC.map((byte, index) => byte ^ digest[index]));
}

function wafBytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(bin);
}

function wafBase64ToBytes(value: string): Uint8Array {
  const bin = atob(value);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * 判断字符串是否已是密文(幂等加密用)。
 * 输入:任意字符串;输出:true 表示已加密(v2 混淆 magic 匹配或旧 dbx1: 前缀)。
 */
async function isWafEncoded(value: string): Promise<boolean> {
  if (value.startsWith(WAF_SQL_PREFIX)) return true;
  try {
    const raw = wafBase64ToBytes(value);
    if (raw.length < 12 + 4 + 16 + 1) return false;
    const masked = raw.slice(12, 16);
    const expected = await wafMaskedMagic((await wafImportKey()).keyBytes, raw.slice(0, 12));
    return masked.every((byte, index) => byte === expected[index]);
  } catch {
    return false;
  }
}

/**
 * 加密单条文本为 v2 无前缀密文(幂等:已加密的原样返回)。
 * 输入:SQL/查询文本或任意自由文本;输出:外观随机的 base64 串。
 * 加密不可用(如非 HTTPS)时退回明文。
 */
export async function encodeSql(sql: string): Promise<string> {
  if (!isWafEncodeEnabled() || (await isWafEncoded(sql))) return sql;
  try {
    const { key, keyBytes } = await wafImportKey();
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(sql)));
    const masked = await wafMaskedMagic(keyBytes, nonce);
    const payload = new Uint8Array(nonce.length + masked.length + cipher.length);
    payload.set(nonce, 0);
    payload.set(masked, nonce.length);
    payload.set(cipher, nonce.length + masked.length);
    return wafBytesToBase64(payload);
  } catch {
    // 加密不可用(如非 HTTPS 环境)时退回明文,保证功能可用
    return sql;
  }
}

/**
 * 递归加密 JSON 值中所有承载 SQL 文本的命名字段(含数组元素与任意嵌套)。
 * 输入:请求体对象/数组/字符串(及当前字段名、父级是否已命中);输出:同形状的新值,
 * 其中命中的字符串字段被替换为 v2 密文(外观随机的 base64),其余字段原样保留。
 * 命中字段名的对象/数组子树整体加密(覆盖 tableFilters 这类"动态键 -> SQL 片段"的映射);
 * 对象键名不参与加密。后端 waf_codec::decode_json_request_body 对请求体整体递归解密,
 * 两侧对称;幂等:已加密字符串原样保留。
 */
export async function encodeSqlDeep(value: unknown, fieldName = "", force = false): Promise<unknown> {
  if (!isWafEncodeEnabled()) return value;
  if (typeof value === "string") {
    return force || (fieldName && isWafSqlField(fieldName)) ? encodeSql(value) : value;
  }
  if (Array.isArray(value)) {
    return Promise.all(value.map((item) => encodeSqlDeep(item, fieldName, force)));
  }
  if (value && typeof value === "object") {
    const matched = force || (fieldName !== "" && isWafSqlField(fieldName));
    const entries = await Promise.all(Object.entries(value as Record<string, unknown>).map(async ([key, item]) => [key, await encodeSqlDeep(item, key, matched)] as const));
    return Object.fromEntries(entries);
  }
  return value;
}
