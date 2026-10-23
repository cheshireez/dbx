# DBX Web 服务器部署手册（含 WAF 加密传输）

> 面向部署运维同学,照抄命令即可完成部署。镜像内已包含前端页面与后端服务
> (单容器全包,监听 4224),并已开启 SQL 载荷加密(防安全网关内容检测误拦)。

---

## 一、前置条件

| 项 | 要求 |
|---|---|
| 服务器 | Linux x86_64(ARM 服务器需用 arm64 镜像) |
| 软件 | Docker 20.10+(`docker -v` 可执行) |
| 网络 | 云安全组放行 TCP 4224(源限网关 IP);对外入口走 HTTPS(见第四节,**必须**) |
| 磁盘 | 镜像加载后约 575MB(tar 144MB)+ 数据卷空间 |

## 二、获取镜像

镜像已构建并导出为 `dbx-waf.tar`(约 144MB,位于仓库根目录
`e:\Projects\personal\dbx\dbx-waf.tar`;已含 `VITE_DBX_WAF_SQL_ENCODE=1` 加密开关,
冒烟验证通过)。

**本地(Windows PowerShell)上传到服务器:**

```powershell
ssh zjplan@你的服务器 "mkdir -p /home/zjplan/tools/dbx-waf"
scp e:\Projects\personal\dbx\dbx-waf.tar zjplan@你的服务器:/home/zjplan/tools/dbx-waf/
```

(如需自行重新导出:`docker save dbx-waf:latest -o dbx-waf.tar`)

**服务器加载:**

```bash
docker load -i /home/zjplan/tools/dbx-waf/dbx-waf.tar
docker images   # 应能看到 dbx-waf  latest(约 575MB)
```

## 三、部署运行

```bash
# 1. 建数据目录(务必挂卷,否则删容器丢数据)
mkdir -p /home/zjplan/tools/dbx-waf/data /home/zjplan/tools/dbx-waf/backups

# 2. 启动容器(应用挂在 /bridge/dbx 子路径下,端口对所有网卡开放)
docker run -d --name dbx --restart unless-stopped \
  -p 4224:4224 \
  -v /home/zjplan/tools/dbx-waf/data:/app/data \
  -v /home/zjplan/tools/dbx-waf/backups:/app/backups \
  -e DBX_WAF_SQL_KEY=dbx-waf-default-key-2026 \
  -e DBX_PUBLIC_BASE_PATH=/bridge/dbx \
  --security-opt seccomp=unconfined \
  dbx-waf:latest

# 3. 看日志确认启动
#    (看到 "Serving DBX Web under context path /bridge/dbx" 即成功)
docker logs -f dbx

# 4. 验证监听地址(应为 0.0.0.0:4224;若显示 127.0.0.1 说明端口被回环限制,外部不通)
ss -tlnp | grep 4224
```

说明:
- `DBX_PUBLIC_BASE_PATH=/bridge/dbx`:应用挂载在该 URL 子路径下,
  访问入口为 `https://你的域名/bridge/dbx/`。前端资源为相对路径、API 按
  location 推断前缀,均自动适配;去掉该变量即回到根路径 `/` 访问。
- `--security-opt seccomp=unconfined`:**本机必需**。该服务器 Docker 默认 seccomp
  过滤会在容器进程启动瞬间拒绝执行(`container_linux.go:340 permission denied`),
  已实测关闭 seccomp 后正常。仅关闭"系统调用白名单"这层加固,容器内是自家
  可信镜像,无任意代码执行入口,不影响加密与鉴权。若日后升级 runc/docker 使
  默认 seccomp 可用,可去掉此参数再验证。
- `-p 4224:4224`:监听所有网卡,供网关/nginx 回源或外部访问。
  **必须配套云安全组放行**(阿里云 ECS 控制台 → 安全组 → 入方向 → TCP 4224,
  源地址只填网关机器 IP,不填 0.0.0.0/0);本机防火墙如有 iptables 规则也需放行。
  若只需本机 nginx 访问、不接受外部直连,可改回 `-p 127.0.0.1:4224:4224`
  (此时外部机器 telnet 4224 不通属正常)。
- `DBX_WAF_SQL_KEY`:SQL 加密口令,必须与镜像构建时的
  `VITE_DBX_WAF_SQL_KEY` 一致(本镜像用默认值 `dbx-waf-default-key-2026`,
  不改密钥时保持上面命令即可)。
- 容器内路径约定:数据 `/app/data`、备份 `/app/backups`、静态页面 `/app/static`(已内置)。

## 四、HTTPS 入口(关键!)

前端 SQL 加密依赖 HTTPS(浏览器 crypto.subtle 仅在 secure context 可用)。
**用 HTTP 访问时前端会静默退回明文,全部请求重新暴露给网关拦截——部署再对也白搭。**

**情形 A:安全网关/负载均衡已对外 HTTPS**
确认网关回源到容器 `http://服务器IP:4224` 即可,服务器不用再配证书。

**情形 B:服务器自己终结 TLS(nginx 示例)**

```nginx
server {
  listen 443 ssl;
  server_name dbx.你的域名;
  ssl_certificate     /etc/nginx/certs/dbx.pem;
  ssl_certificate_key /etc/nginx/certs/dbx.key;

  # 应用挂在 /bridge/dbx 子路径:路径原样透传(结尾不能带 URI,不能剥前缀)
  location /bridge/dbx {
    proxy_pass http://127.0.0.1:4224;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_buffering off;          # AI 流式接口(SSE)必需
    proxy_read_timeout 3600s;     # 长查询/长对话
    client_max_body_size 1024m;   # 大文件导入(与容器内上限一致)
  }

  # 兜底:根路径请求转到入口
  location = / {
    return 302 /bridge/dbx/;
  }
}
```

> 若安全网关直接回源容器(不经本机 nginx),配置网关的回源规则:
> 对外路径 `/bridge/dbx/*` → 回源 `http://服务器:4224/bridge/dbx/*`(同样不剥前缀)。

## 五、首次初始化

1. 浏览器打开 `https://你的域名/bridge/dbx/`(不带斜杠会自动跳转)
2. 首次访问会引导设置管理员密码(数据存于 `/app/data`,请牢记)
3. 登录后先建一个测试连接验证数据库连通

## 六、启用 Web MCP(Streamable HTTP)

Web 版 MCP 服务把 Streamable HTTP 端点挂在应用子路径下(本部署即
`https://你的域名/bridge/dbx/mcp`),供 n8n MCP Client、Claude、Cursor 等
外部客户端接入。**不启用时该端点返回 404**;不新增端口(复用 4224),
安全组无需变更;鉴权为 `Bearer` token + Host 白名单。

### 方式 A:环境变量托管(推荐,服务器部署)

在第三节 `docker run` 命令中追加环境变量后重建容器(删旧容器重跑,
数据卷保留):

```bash
docker rm -f dbx
docker run -d --name dbx --restart unless-stopped \
  -p 4224:4224 \
  -v /home/zjplan/tools/dbx-waf/data:/app/data \
  -v /home/zjplan/tools/dbx-waf/backups:/app/backups \
  -e DBX_WAF_SQL_KEY=dbx-waf-default-key-2026 \
  -e DBX_PUBLIC_BASE_PATH=/bridge/dbx \
  -e DBX_WEB_MCP_TOKEN='换成随机长口令' \
  -e DBX_WEB_MCP_ALLOWED_HOSTS='你的域名' \
  --security-opt seccomp=unconfined \
  dbx-waf:latest
```

| 变量 | 必填 | 说明 |
|---|---|---|
| `DBX_WEB_MCP_TOKEN` | 是 | Bearer token,自备随机长口令(如 `openssl rand -hex 32`);或改用 `DBX_WEB_MCP_TOKEN_FILE` 指向文件(**二选一**,同时设置会启动报错) |
| `DBX_WEB_MCP_ALLOWED_HOSTS` | 是 | 逗号分隔的 Host 白名单,**填外部访问域名**(不是 IP)。请求的 Host 头不在此列返回 403 |
| `DBX_WEB_MCP_ALLOWED_ORIGINS` | 否 | 浏览器客户端的 Origin 白名单(如 `https://你的域名`);纯服务端客户端可不填 |

特点:设置环境变量即强制启用,页面内"MCP HTTP 服务"设置变为只读
(部署托管,token 不回显);换 token 需修改环境变量并重建容器。

### 方式 B:页面内开关(前提:已设管理员密码)

完成第五节首次初始化后,登录 → 设置 → MCP HTTP 服务 → 开启。token 自动
生成并存于数据卷,Host 白名单在页面内填写。**管理员密码未设置时管理接口
返回 403**(`Web MCP management requires password-protected DBX Web`)。

### 网关/WAF 放行(必读)

MCP 客户端发送的是**明文 JSON-RPC**,工具参数含 SQL(如 `dbx_execute_query`
的 `sql` 字段)。`/mcp` 端点不经过前端加密通道,若安全网关对该路径做请求体
内容检测会直接拦截——**网关需对 `/bridge/dbx/mcp` 路径放行(跳过 SQL 注入
检测规则)**,否则客户端 initialize 即被拦。

nginx(第四节配置)无需改动:`proxy_buffering off` 已满足 SSE 流式响应,
`proxy_set_header Host $host` 原样透传外部域名,保证 Host 白名单校验正确。

### 客户端接入与验证

端点:`https://你的域名/bridge/dbx/mcp`(POST-only,无会话;GET/DELETE 返回
405 属正常)

服务器本机冒烟(显式 Host 头命中白名单,绕过本机 127.0.0.1 不在白名单的问题):

```bash
curl -s -i -X POST http://127.0.0.1:4224/bridge/dbx/mcp \
  -H 'Host: 你的域名' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Authorization: Bearer 你的token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
# 期望 HTTP 200,返回 initialize 响应(JSON 或 SSE)
```

MCP 客户端配置:
- URL:`https://你的域名/bridge/dbx/mcp`
- Header:`Authorization: Bearer 你的token`

## 七、验收清单

| # | 检查项 | 通过标准 |
|---|---|---|
| 1 | HTTPS 打开登录页 | 访问 `https://你的域名/bridge/dbx/` 无证书告警,登录成功 |
| 2 | 执行 `SELECT * FROM users WHERE name='admin' --` | 查询正常返回,不被网关拦(无 405 等) |
| 3 | F12 → Network 看该请求体 | `sql` 是**无前缀随机 base64**,不含 SQL 关键字、`dbx1`、`DBX1` |
| 4 | 同一条 SQL 执行两次 | 两次密文不同(随机 IV,无固定签名) |
| 5 | 常用操作各来一遍 | 条件更新、保存 SQL、导出、AI 对话(消息含 SQL)均不被拦 |
| 6 | `docker restart dbx` 后 | 数据/配置仍在(挂卷生效) |
| 7 | MCP 端点(若启用) | 第六节 curl 返回 HTTP 200 与 initialize 响应 |
| 8 | 外部 MCP 客户端(若启用) | `tools/list` 返回含 `dbx_execute_query` 等工具 |

## 八、日常运维

```bash
docker logs -f --tail 200 dbx      # 看日志
docker restart dbx                 # 重启
docker stop dbx && docker rm dbx   # 停止并删除(数据在卷里,不丢)

# 升级版本:load 新镜像后重建容器
docker load -i /home/zjplan/tools/dbx-waf/dbx-waf-new.tar
docker stop dbx && docker rm dbx
# 重新执行第三节的 docker run 即可

# 备份:直接打包数据目录
tar czf /home/zjplan/tools/dbx-waf/backups/dbx-backup-$(date +%F).tar.gz -C /home/zjplan/tools/dbx-waf data
```

## 九、密钥轮换(可选,三处必须同步)

生产建议把默认密钥换成自定义口令。换钥需要**重新构建镜像**并同步三处:

| 位置 | 参数/文件 |
|---|---|
| 镜像构建 | `docker build ... --build-arg VITE_DBX_WAF_SQL_KEY=新口令`(构建须在换钥后重跑) |
| 容器运行 | `-e DBX_WAF_SQL_KEY=新口令` |
| n8n 工作流 | "加密SQL"节点代码中 `const secret = '新口令'` |

注意:换钥后旧客户端(旧前端页面)密文将无法解密,请整体升级。

## 十、故障排查

| 现象 | 原因与处理 |
|---|---|
| 启动即报 `container_linux.go:340 permission denied` | 本机 Docker 默认 seccomp 拦截 → docker run 加 `--security-opt seccomp=unconfined`(见第三节命令) |
| 另一台机器 telnet 4224 不通(本机通) | ① `ss -tlnp \| grep 4224` 显示 `127.0.0.1` → 端口被回环限制,改 `-p 4224:4224` 重建;② 显示 `0.0.0.0` 仍不通 → 云安全组/防火墙未放行 4224,源填请求方 IP |
| 访问 `/bridge/dbx/` 404 或页面空白 | ① nginx `proxy_pass` 结尾带了 URI 把前缀剥掉了 → 去掉;② 容器没设 `DBX_PUBLIC_BASE_PATH=/bridge/dbx` → 加上重建;③ 日志应有 "Serving DBX Web under context path /bridge/dbx" |
| 查询被网关拦(405 等),F12 看请求体是明文 SQL | 用 HTTP 访问了 → 必须走 HTTPS 入口(见第四节) |
| 请求体是密文但后端报 "decrypt failed" | 前端密钥与容器 `DBX_WAF_SQL_KEY` 不一致 → 对齐两处 |
| 请求体是密文但后端当明文执行报语法错 | 密钥不一致导致 magic 不匹配被当明文 → 同上,对齐密钥 |
| 页面打不开 | `docker logs dbx` 看报错;确认 4224 端口与 nginx `proxy_pass` 地址 |
| AI 对话卡住无输出 | nginx 缺 `proxy_buffering off` → 按第四节补配置 |
| 重启后数据丢失 | 忘记挂卷 `/app/data` → 重建容器并挂卷 |
| n8n 工作流报解密失败 | n8n "加密SQL"节点的 `secret` 与容器密钥不一致 → 同步 |
| MCP 端点 404 | 未启用:方式 A 缺 `DBX_WEB_MCP_TOKEN`(或 `_FILE`)/方式 B 未在页面开启 → 配置后重建或保存 |
| MCP 端点 403(host-not-allowed) | `DBX_WEB_MCP_ALLOWED_HOSTS` 未包含请求实际 Host(外部域名) → 补上重建;日志搜 `host-not-allowed` 可确认 |
| MCP 端点 401 | `Authorization: Bearer <token>` 缺失或 token 不对 |
| MCP 客户端 initialize 即被网关拦(405/400) | 网关对 `/bridge/dbx/mcp` 做请求体内容检测 → 按第六节放行该路径 |
| MCP 页面设置保存 403 | 管理员密码未设置(或 demo 模式) → 先完成第五节初始化 |

## 十一、安全说明(知悉)

本加密方案定位是**防安全网关内容检测误拦**,不是面向攻击者的保密措施:
密钥随前端 JS 分发,可被逆向提取;登录鉴权、数据安全由账号体系与 HTTPS 承担。
详见 `docs/internal/waf-payload-encryption.zh-CN.md`。
