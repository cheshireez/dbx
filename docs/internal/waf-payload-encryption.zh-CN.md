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
- 传输格式:`sql` / `statements` 字段以 `dbx1:` 前缀 + Base64(nonce||密文||tag)。
- 覆盖范围:
  - Web 前端:6 个查询执行接口(`execute`、`execute-multi`、`execute-batch`、
    `execute-script`、`execute-script-2pc`、`execute-in-transaction`)。
  - MCP Server:查询接口(`/api/query/execute`)。
- 后端 `dbx-web` 对 `dbx1:` 前缀无条件解密,同时兼容明文(默认行为不变)。

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

- 浏览器执行 `SELECT * FROM ...`:Network 中请求体 `sql` 应为 `dbx1:` 开头,查询正常返回。
- MCP:可抓包确认 `/api/query/execute` 请求体中的 `sql` 为 `dbx1:` 密文。

## 残余风险与说明

- 密钥随客户端(JS 包 / MCP 二进制)分发,可被提取,因此本方案是"防内容检测",
  不是面向真实攻击者的保密措施;传输安全仍依赖 HTTPS。
- 若安全网关后续对高熵/Base64 密文增加检测规则,本方案可能失效,届时需重新评估
  (白名单放行或改造查询通道)。
- 本方案是对既有网关内容检测策略的兼容性设计,请内部按流程知悉留档。
