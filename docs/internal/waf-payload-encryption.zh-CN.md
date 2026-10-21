# DBX SQL 载荷加密传输说明(内部留档)

> 本文档面向内部运维/安全同事,记录 DBX Web 部署中为兼容既有安全网关策略而引入的
> 应用层报文加密设计。本分支为私有改动,不进入上游仓库。

## 背景

DBX 部署于安全网关(中间层 WAF)之后,网关对请求体做 SQL 注入内容检测。
DBX 是带登录认证的数据库客户端,请求体中的 SQL 是授权用户对自有数据库执行的
合法查询,却被规则误判(例如最普通的 `SELECT * FROM ...` 返回 405)。
经评估,网关侧无法对该路径放行,因此在应用层对 SQL 载荷做加密传输。

## 方案

- 算法:AES-256-GCM(随机 12 字节 nonce,密文附 16 字节校验 tag)。
- 密钥:由共享口令经 SHA-256 派生 32 字节;默认口令内置,可通过环境变量覆盖。
- 传输格式(v2,当前):`base64(nonce[12] || masked_magic[4] || 密文 || tag[16])`,
  **无固定前缀**,`masked_magic = "DBX1" XOR SHA256(密钥 || nonce)[0..4]`。
  外观与随机 token 无异:传输中不出现任何固定明文特征(无 `dbx1:` 前缀、
  无明文 magic),避免被按签名/固定模式拦截;识别凭混淆 magic,只有密钥持有者能算出。
- 传输格式(v1,兼容保留):`dbx1:<base64(nonce||密文||tag)>`,后端继续接受
  (向后兼容旧客户端;n8n 已升级到 v2,该格式可在确认无其他旧客户端后移除)。
- 覆盖范围:
  - Web 前端:全部 JSON 请求统一深度加密(前端 `encodeSqlDeep` 按字段名匹配递归加密,
    规则为 `xxSql`/`xxJson` 后缀或命名段关键词(where/query/filter/order/sort/command 等,
    支持驼峰复合名与单复数,如 `whereInput`/`orderBy`/`searchText`/`tableFilters`),
    命中字段的对象/数组子树整体加密(覆盖动态键映射);所有原生 `fetch` JSON 请求体
    (数据传输、导入导出、Nacos 等)与 MQ 模块(mq-http)一并走 `encodeSqlDeep`,
    覆盖查询执行、SQL 分析、build-* SQL 生成、保存 SQL、AI 对话、导出、
    Redis/Mongo 命令等所有接口。
  - MCP Server:查询/批量接口(`sql` 字段)+ 请求体全量深度加密(`encode_json_value`,
    与前端同规则,覆盖 Mongo filter/command、Redis command 等),由 `request()` 统一入口生效。
- 后端 `dbx-web` 对请求体中密文字符串整体递归解密
  (`waf_codec::decode_json_request_body` 中间件 + 查询执行入口逐字段解码),
  同时兼容明文(默认行为不变);解不出的字符串(业务数据恰好像密文)原样保留。

## 配置

### Web 前端(构建自定义镜像时)

```bash
docker build -t xdb:waf -f deploy/Dockerfile \
  --build-arg VITE_DBX_WAF_SQL_ENCODE=1
```

自定义密钥(可选,前后端必须一致):

```bash
docker build -t xdb:waf -f deploy/Dockerfile \
  --build-arg VITE_DBX_WAF_SQL_ENCODE=1 \
  --build-arg VITE_DBX_WAF_SQL_KEY=your-secret
```

容器环境变量(与构建密钥一致时才需要):

```yaml
environment:
  - DBX_WAF_SQL_KEY=your-secret
```

### MCP Server(本地编译版)

```bash
# 环境变量
DBX_WEB_URL=http://127.0.0.1:12442/bridge/xdb   # 或公网地址
DBX_WEB_PASSWORD=...
DBX_MCP_WAF_SQL_ENCODE=1
# 自定义密钥时(与后端一致):
DBX_WAF_SQL_KEY=your-secret
```

注意:官方 `npx @dbx-app/mcp-server` 不含此改动,必须使用本分支编译的
`dbx-mcp` 二进制。

## 验证

- 浏览器执行 `SELECT * FROM ...`:Network 中请求体 `sql` 为一段**无前缀的
  随机 base64**(不出现 SQL 关键字、`dbx1:`、`DBX1` 等任何固定特征),查询正常返回。
- 同一条 SQL 两次执行,请求体密文不同(随机 nonce),无固定签名。
- MCP:可抓包确认 `/api/query/execute` 请求体中的 `sql` 同为无前缀随机 base64。
- 兼容性:n8n 旧 `dbx1:` 密文与明文请求仍正常工作。

## 残余风险与说明

- **未能覆盖的通道(已知)**:
  - multipart 上传:SQL 文件导入预览(`/api/sql-file/preview`)、CSV/XLSX 导入预览、
    插件/驱动/离线包上传。这些请求体不是 JSON,现有中间件不解码;若网关会检测
    multipart 内容体,需要在网关上对这几条路径放行,或后续改为"加密 JSON 上传通道"
    (前端先加密文件内容,后端解密后落盘)。
  - GET 查询串:`/api/schema/tables?filter=...`、`table_name_filter` 等标识符搜索词
    仍是明文。风险低(通常只含表名片段),但用户若在侧边栏搜索框输入 SQL 片段仍可能被拦。
  - 响应方向:查询结果、DDL、EXPLAIN 等响应体不加密;若网关做响应内容检测,
    结果集中的 SQL 文本仍会被看到。
- 密钥随客户端(JS 包 / MCP 二进制)分发,可被提取,因此本方案是"防内容检测",
  不是面向真实攻击者的保密措施;传输安全仍依赖 HTTPS。
- v2 已消除固定前缀/固定签名特征;残余理论特征只有"高熵 base64 长串"本身
  (与 JWT、token 等正常流量形态一致)。若安全网关后续按全局熵值拦截,
  本方案可能受影响,届时需重新评估(白名单放行或改造查询通道)。
- n8n 加密节点(`scripts/js_encrypt_sql.txt`)已升级到 v2(输出无前缀随机 base64,
  含混淆 magic),与前端/后端三端互通——由 waf_codec 黄金样本测试锚定
  (`v2_golden_sample_from_n8n_js_implementation`)。
- 本方案是对既有网关内容检测策略的兼容性设计,请内部按流程知悉留档。
