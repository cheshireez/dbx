#!/usr/bin/env bash
# DBX Web 版本升级（在服务器上执行）：备份数据 → 加载新镜像 → 保留旧镜像 → 重建容器 → 健康检查
#
# 用法：
#   bash remote-upgrade.sh <tar路径> [镜像tag] [容器名] [端口] [contextPath] [wafKey] [数据目录] [备份目录]
#
# 示例：
#   bash remote-upgrade.sh /home/zjplan/tools/dbx-waf/dbx-waf-new.tar
#
# 回滚（新版本异常时）：
#   docker rm -f dbx && docker run -d --name dbx --restart unless-stopped \
#     -p 4224:4224 -v /home/zjplan/tools/dbx-waf/data:/app/data \
#     -v /home/zjplan/tools/dbx-waf/backups:/app/backups \
#     -e DBX_WAF_SQL_KEY=dbx-waf-default-key-2026 -e DBX_PUBLIC_BASE_PATH=/bridge/dbx \
#     --security-opt seccomp=unconfined dbx-waf:previous
set -euo pipefail

TAR=${1:?用法: remote-upgrade.sh <tar路径> [镜像tag] [容器名] [端口] [contextPath] [wafKey] [数据目录] [备份目录]}
IMAGE_TAG=${2:-dbx-waf:latest}
CONTAINER=${3:-dbx}
PORT=${4:-4224}
BASE_PATH=${5:-/bridge/dbx}
WAF_KEY=${6:-dbx-waf-default-key-2026}
DATA_DIR=${7:-/home/zjplan/tools/dbx-waf/data}
BACKUP_DIR=${8:-/home/zjplan/tools/dbx-waf/backups}

echo "==> 0. 当前状态"
docker ps -a --filter "name=^/${CONTAINER}$" --format '   容器 {{.Names}} | {{.Status}} | 镜像 {{.Image}}' || true
docker images "$IMAGE_TAG" --format '   本地镜像 {{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' 2>/dev/null || true
OLD_IMAGE_ID=$(docker inspect -f '{{.Image}}' "$CONTAINER" 2>/dev/null || true)
if [ -n "${OLD_IMAGE_ID}" ]; then
  echo "   旧容器镜像ID: ${OLD_IMAGE_ID}"
else
  echo "   未发现名为 ${CONTAINER} 的容器（按首次部署处理）"
fi

echo "==> 1. 备份数据目录"
mkdir -p "$BACKUP_DIR"
STAMP=$(date +%F-%H%M%S)
if [ -d "$DATA_DIR" ]; then
  tar czf "${BACKUP_DIR}/dbx-data-${STAMP}.tar.gz" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")"
  echo "   已备份: ${BACKUP_DIR}/dbx-data-${STAMP}.tar.gz ($(du -h "${BACKUP_DIR}/dbx-data-${STAMP}.tar.gz" | cut -f1))"
else
  echo "   数据目录 ${DATA_DIR} 不存在，跳过备份"
fi

echo "==> 2. 加载新镜像"
docker load -i "$TAR"
NEW_IMAGE_ID=$(docker images -q "$IMAGE_TAG" | head -1)
echo "   已加载: ${IMAGE_TAG} (${NEW_IMAGE_ID})"

echo "==> 3. 保留旧镜像用于回滚"
if [ -n "${OLD_IMAGE_ID}" ]; then
  docker tag "${OLD_IMAGE_ID}" dbx-waf:previous
  echo "   旧镜像已打标: dbx-waf:previous"
fi

echo "==> 4. 重建容器"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --restart unless-stopped \
  -p "${PORT}:4224" \
  -v "${DATA_DIR}:/app/data" \
  -v "${BACKUP_DIR}:/app/backups" \
  -e DBX_WAF_SQL_KEY="$WAF_KEY" \
  -e DBX_PUBLIC_BASE_PATH="$BASE_PATH" \
  --security-opt seccomp=unconfined \
  "$IMAGE_TAG" >/dev/null
echo "   容器已启动: $CONTAINER"

echo "==> 5. 健康检查"
if ! command -v curl >/dev/null 2>&1; then
  echo "   宿主机没有 curl，改为检查容器状态（HTTP 请自行访问 ${BASE_PATH}/）"
  sleep 5
  docker ps --filter "name=^/${CONTAINER}$" --format '   {{.Status}}'
  docker logs --tail 12 "$CONTAINER" 2>&1 | sed 's/^/   /'
  exit 0
fi

OK=0
for _ in $(seq 1 30); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}${BASE_PATH}/" 2>/dev/null || true)
  if [ "$CODE" = "200" ]; then OK=1; break; fi
  sleep 2
done
if [ "$OK" = "1" ]; then
  echo "   HTTP ${BASE_PATH}/ -> 200"
else
  echo "   !! 健康检查未通过（最近日志如下）"
  docker logs --tail 30 "$CONTAINER" 2>&1 | sed 's/^/   /'
  echo "   回滚: 见本脚本头部注释，用 dbx-waf:previous 重建容器"
  exit 1
fi

echo "==> 6. 启动日志"
docker logs --tail 12 "$CONTAINER" 2>&1 | sed 's/^/   /'
echo
echo "完成。浏览器端记得 Ctrl+F5 硬刷新，避免命中旧前端 bundle。"
