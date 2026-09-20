#!/usr/bin/env bash
# 一键把 VPetMod-Scanner 部署到一台 Linux Docker 主机。
#
# 特点：镜像基于 scratch，docker build 不拉取任何镜像层，因此目标机可以完全无法访问
# dockerhub / 外网。二进制在本机（有 Go）交叉编译好后 scp 过去，目标机只做 build+run。
#
# 用法：
#   HOST=ycxom@192.168.115.2 TOKEN=your-secret ./deploy.sh
# 可选环境变量：
#   PORT=8740             宿主机对外端口
#   NAME=vpetscan         容器名
#   DATA=/opt/vpetscan    宿主机数据目录（持久化任务/审核记录）
#   MAX_UPLOAD_MB=256
#   SSH_OPTS=             追加给 ssh/scp 的参数（如 -i key）
set -euo pipefail

HOST=${HOST:?请设置 HOST，例如 HOST=user@1.2.3.4}
PORT=${PORT:-8740}
NAME=${NAME:-vpetscan}
DATA=${DATA:-/opt/vpetscan/data}
TOKEN=${TOKEN:-}
MAX_UPLOAD_MB=${MAX_UPLOAD_MB:-256}
SSH_OPTS=${SSH_OPTS:-}
REMOTE_DIR=${REMOTE_DIR:-/tmp/vpetscan-deploy}

here=$(cd "$(dirname "$0")/.." && pwd)
echo "[1/5] 交叉编译静态二进制 (linux/amd64)..."
( cd "$here" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o deploy/vpetscan-linux-amd64 . )

echo "[2/5] 上传构建上下文到 $HOST:$REMOTE_DIR ..."
# shellcheck disable=SC2086
ssh $SSH_OPTS "$HOST" "mkdir -p $REMOTE_DIR"
# shellcheck disable=SC2086
scp $SSH_OPTS "$here/deploy/Dockerfile" "$here/deploy/vpetscan-linux-amd64" "$HOST:$REMOTE_DIR/"

echo "[3/5] 目标机离线构建镜像 (FROM scratch，不联网)..."
# shellcheck disable=SC2086
ssh $SSH_OPTS "$HOST" "cd $REMOTE_DIR && docker build -t vpetscan:latest ."

echo "[4/5] 重启容器..."
env_token=""
[ -n "$TOKEN" ] && env_token="-e VPETSCAN_TOKEN=$TOKEN"
# shellcheck disable=SC2086
ssh $SSH_OPTS "$HOST" "
  docker rm -f $NAME >/dev/null 2>&1 || true
  mkdir -p $DATA
  docker run -d --name $NAME --restart unless-stopped \
    -p $PORT:8740 -v $DATA:/data $env_token \
    vpetscan:latest serve -listen 0.0.0.0:8740 -data /data \
      -token \${VPETSCAN_TOKEN:-} -max-upload-mb $MAX_UPLOAD_MB
"

echo "[5/5] 健康检查..."
# shellcheck disable=SC2086
ssh $SSH_OPTS "$HOST" "
  for i \$(seq 1 10); do
    if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then
      printf 'GET /healthz HTTP/1.0\r\n\r\n' >&3; head -c 200 <&3; exec 3>&- 3<&-; exit 0
    fi
    sleep 1
  done
  echo '健康检查超时'; docker logs --tail 30 $NAME; exit 1
"
echo
echo "完成：http://<主机IP>:$PORT/  （审核页面）"
[ -z "$TOKEN" ] && echo "警告：未设置 TOKEN，接口无鉴权，请勿暴露到公网。"
