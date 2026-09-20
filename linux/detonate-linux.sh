#!/usr/bin/env bash
# Linux(Wine) 动态引爆 + 采集。资源轻量：不跑完整 VPet，只用最小 harness 触发 boot 链。
#
# ⚠️ Wine 不是安全边界。真样本务必：本机先拍可回滚快照；用本脚本的 --isolate（bwrap+网络命名空间，
#    仅放行 sinkhole）；跑完回滚快照。不要在生产/含真实账号的机器上跑真样本。
#
# 两种模式：
#   --mock                          用良性诱饵验证整条流水线（读金丝雀+回连 sinkhole），安全
#   --boot <native/boot.dll> [ord]  用 harness 触发真实 boot 加载器（真引爆，需隔离+快照）
#
# --pin-c2 <域名列表>   把已知 C2 域名钉到沙箱内 sinkhole 并做 TLS MITM（仍断网，不碰真实 C2）：
#   /etc/hosts 把域名→127.0.0.1（跑完 trap 恢复）；bwrap netns 里 lo 上 sinkhole 真应答，
#   443 用现生成的证书终结 TLS（临时装入系统信任库，跑完移除）→ 样本"连上了 C2"实际只到
#   本机，外传 POST 被完整解密落盘。netns 无出网路由，比纯断网还绝（DNS 都不用出网）。
#
# 用法示例（验证可行性）：
#   sudo ./detonate-linux.sh --mock --sink 127.0.0.1 --seconds 25 --out run1
# 真样本：
#   sudo ./detonate-linux.sh --boot /samples/mod/native/helper_5e.dll --sink 10.7.0.1 --isolate --seconds 180 --out run1
# 钉住 C2 抓外传：
#   sudo ./detonate-linux.sh --boot boot.dll --sink 127.0.0.1 --seconds 180 --out run-pin \
#        --isolate --pin-c2 bvdpp.top,www.bvdpp.top
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

MODE=""; TARGET=""; ORD="1"; SINK="127.0.0.1"; SECONDS_RUN=60; OUT="run-$(date +%Y%m%d-%H%M%S)"; ISOLATE=0; SERVE=""; PIN=""
while [ $# -gt 0 ]; do case "$1" in
  --mock) MODE=mock;;
  --boot) MODE=boot; TARGET="$2"; shift; if [[ "${2:-}" =~ ^[0-9]+$ ]]; then ORD="$2"; shift; fi;;
  --sink) SINK="$2"; shift;;
  --seconds) SECONDS_RUN="$2"; shift;;
  --out) OUT="$2"; shift;;
  --serve) SERVE="$2"; shift;;
  --isolate) ISOLATE=1;;
  --pin-c2) PIN="$2"; shift;;
  *) echo "未知参数 $1"; exit 2;;
esac; shift; done
[ -z "$MODE" ] && { echo "需指定 --mock 或 --boot <dll>"; exit 2; }

mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
# +winhttp：Wine 自己的 winhttp 跟踪在 TLS 加密前打出请求 URL，白捡一层外联证据。
export WINEARCH="${WINEARCH:-win64}"; export WINEPREFIX="$OUT/prefix"; export WINEDEBUG="${WINEDEBUG:-fdll+seh+winhttp}"; export DISPLAY="${DISPLAY:-}"
# /run/user/<uid>：wine 硬编码在这里放 wineserver socket；systemd 服务上下文没有它（交互式
# ssh+sudo 会话由 pam_systemd 建好，所以手动能跑）。缺了它 wine 回退到 /tmp——而 /tmp 是 450M
# tmpfs 常被 Wine 前缀撑爆 → wineserver socket 创建失败 → SIGABRT（free(): invalid pointer，
# 到不了 LoadLibrary）。这里补建，bwrap --dev-bind / / 会把它带进沙箱。
RUID="$(id -u)"
[ -d "/run/user/$RUID" ] || { mkdir -p "/run/user/$RUID" && chmod 700 "/run/user/$RUID"; }
export XDG_RUNTIME_DIR="/run/user/$RUID"
WINE="$(command -v wine64 || command -v wine)"
echo "[*] 输出: $OUT  WINEPREFIX=$WINEPREFIX  isolate=$ISOLATE"

[ -n "$WINE" ] || { echo "缺 wine/wine64：sudo apt-get install -y wine64"; exit 1; }
command -v strace  >/dev/null || { echo "缺 strace：sudo apt-get install -y strace"; exit 1; }
command -v tcpdump >/dev/null || echo "[!] 无 tcpdump，跳过抓包（sudo apt-get install -y tcpdump 可启用）"

# ---- --pin-c2：钉住 C2 域名到沙箱内 sinkhole + TLS MITM（仍断网，绝不碰真实 C2）----
if [ -n "$PIN" ] && [ "$MODE" = mock ]; then
  echo "[!] --mock 不组合 --pin-c2（mock 的回连地址走 env 注入，不需要钉域名）——忽略 pin"
  PIN=""
fi
if [ -n "$PIN" ] && ! command -v openssl >/dev/null; then
  echo "[!] 缺 openssl，无法生成 MITM 证书——--pin-c2 降级（443 只记录 SNI）"; PIN=""
fi
if [ -n "$PIN" ]; then
  command -v bwrap >/dev/null || { echo "[!] --pin-c2 需要 bwrap（网络隔离是底线，见 --isolate）"; exit 1; }
  ISOLATE=1  # 钉域名=诱导连接，必须独占 netns（无出网路由），比纯断网还严
  mkdir -p "$OUT/mitm"
  SAN=""; for d in ${PIN//,/ }; do SAN+="DNS:${d},"; done; SAN="${SAN%,}"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
    -keyout "$OUT/mitm/srv.key" -out "$OUT/mitm/srv.crt" \
    -subj "/CN=${PIN%%,*}" -addext "subjectAltName=$SAN" >/dev/null 2>&1
  [ -s "$OUT/mitm/srv.crt" ] || { echo "[!] MITM 证书生成失败——--pin-c2 降级（443 只记录 SNI）"; PIN=""; }
fi
HOSTS_PINNED=0; TRUSTED=0
if [ -n "$PIN" ]; then
  # /etc/hosts 与系统信任库在共享文件系统上改（bwrap --dev-bind / /，沙箱内同样生效），trap 恢复。
  # 先清残留 marker 块（上次异常退出没跑 trap 也不至于留死域名）。
  sed -i '/# BEGIN vpetdyn-pin/,/# END vpetdyn-pin/d' /etc/hosts 2>/dev/null || true
  { echo "# BEGIN vpetdyn-pin"; echo "127.0.0.1 ${PIN//,/ }"; echo "# END vpetdyn-pin"; } >> /etc/hosts
  HOSTS_PINNED=1
  if [ -d /usr/local/share/ca-certificates ] && command -v update-ca-certificates >/dev/null 2>&1; then
    cp "$OUT/mitm/srv.crt" /usr/local/share/ca-certificates/vpetdyn-mitm.crt
    update-ca-certificates >/dev/null 2>&1 && TRUSTED=1
  fi
  cleanup_pin() {
    [ "$HOSTS_PINNED" = 1 ] && sed -i '/# BEGIN vpetdyn-pin/,/# END vpetdyn-pin/d' /etc/hosts 2>/dev/null || true
    if [ "$TRUSTED" = 1 ]; then
      rm -f /usr/local/share/ca-certificates/vpetdyn-mitm.crt
      update-ca-certificates >/dev/null 2>&1 || true
    fi
    return 0
  }
  trap cleanup_pin EXIT
  if [ "$TRUSTED" = 1 ]; then
    echo "[*] --pin-c2: ${PIN//,/ } → 127.0.0.1（hosts 钉住）；MITM 证书已装入系统信任库（跑完自动移除）"
  else
    echo "[!] --pin-c2: 域名已钉住，但 MITM 证书未能装入信任库（update-ca-certificates 不可用？）——TLS 握手可能失败，退回仅记录 ClientHello/SNI"
  fi
fi

echo "[1/6] 初始化 Wine 前缀（离线，无 mono/gecko）..."
WINEDLLOVERRIDES="mscoree,mshtml=" "$WINE" wineboot -i >/dev/null 2>&1 || true

echo "[2/6] 种植金丝雀凭证..."
# 先生成 local.vdf 令牌并用 DPAPI 加密成 ConnectCache blob（同一 Wine 用户上下文，
# 样本 CryptUnprotectData 能解开、明文令牌进上传数据=外发铁证）。protectkey 不可用时
# set-canaries 自动回退占位 hex（解密失败但读取行为仍被 strace 记录）。
PROTECTKEY=""; for p in "$HERE/protectkey.exe" "$HERE/bin/protectkey.exe"; do [ -f "$p" ] && PROTECTKEY="$p" && break; done
DECOY=""; for p in "$HERE/steam.exe" "$HERE/bin/steam.exe"; do [ -f "$p" ] && DECOY="$p" && break; done
LOCALVDF_TOKEN="CANARY-$(cat /proc/sys/kernel/random/uuid | tr -d - | tr 'a-z' 'A-Z')"
LOCALVDF_BLOB=""
if [ -n "$PROTECTKEY" ]; then
  LOCALVDF_BLOB="$(WINEPREFIX="$WINEPREFIX" WINEDLLOVERRIDES="mscoree,mshtml=" DISPLAY= "$WINE" "$PROTECTKEY" "ConnectCache canary $LOCALVDF_TOKEN" 2>/dev/null | tr -d '\r\n')" || true
  case "$LOCALVDF_BLOB" in *[!0-9a-fA-F]*|"") LOCALVDF_BLOB="";; esac
  echo "[*] DPAPI blob: ${LOCALVDF_BLOB:+生成成功}${LOCALVDF_BLOB:-生成失败，用占位 hex}"
fi
( cd "$OUT" && WINEPREFIX="$WINEPREFIX" LOCALVDF_TOKEN="$LOCALVDF_TOKEN" LOCALVDF_BLOB="$LOCALVDF_BLOB" \
    STEAM_DECOY_EXE="$DECOY" bash "$HERE/set-canaries-linux.sh" canaries.txt )
PRIMARY="$(cat "$OUT/canaries.txt.primary")"
JWT_TOKEN="$(cat "$OUT/canaries.txt.jwttoken" 2>/dev/null || true)"

echo "[3/6] 启动 sinkhole ..."
SARGS=(--ip "$SINK" --bind 0.0.0.0 --log "$OUT/sink.jsonl" --canary-file "$OUT/canaries.txt" --dump-dir "$OUT/requests")
[ -n "$SERVE" ] && SARGS+=(--serve "$SERVE")
[ -n "$PIN" ] && SARGS+=(--tls-cert "$OUT/mitm/srv.crt" --tls-key "$OUT/mitm/srv.key")
SINKHOLE=""; for p in "$HERE/dynamic/sinkhole.py" "$HERE/../dynamic/sinkhole.py" "$HERE/sinkhole.py"; do [ -f "$p" ] && SINKHOLE="$p" && break; done
[ -n "$SINKHOLE" ] || { echo "找不到 sinkhole.py"; exit 1; }
SINK_PID=""
if [ -z "$PIN" ]; then
  python3 "$SINKHOLE" "${SARGS[@]}" >"$OUT/sinkhole.out" 2>&1 &
  SINK_PID=$!; sleep 1
else
  # pin 模式：sinkhole 必须在沙箱 netns 里（unshare-net 下宿主进程与沙箱互相不可达），
  # 由 [4/6] 的内层脚本拉起（先 ip link set lo up）。
  echo "    (pin 模式：sinkhole + tcpdump 在沙箱网络命名空间内启动，见 [4/6])"
fi

if [ -z "$PIN" ] && command -v tcpdump >/dev/null; then
  echo "[3b] 启动 tcpdump ..."
  ( tcpdump -i any -s 0 -w "$OUT/capture.pcap" >/dev/null 2>&1 & echo $! > "$OUT/tcpdump.pid" ) || true
fi
# pin 模式的 tcpdump 同样挪进沙箱（宿主 tcpdump 抓不到 netns 内 lo 上的流量）。

# 快照前
find "$WINEPREFIX/drive_c" -type f -printf '%p\t%s\n' 2>/dev/null | sort > "$OUT/files-before.txt" || true

echo "[4/6] 引爆（$SECONDS_RUN 秒）..."
# --seccomp-bpf：只在被过滤的 syscall 上 ptrace-stop。没有它，strace -f 对 wine 线程的
# clone-attach 竞态会让 wine 页错误崩溃（读 0x7FFF00000000），boot 链根本跑不起来。
STRACE=(strace -f -ff -e trace=%file,%network,%process -s 200 -o "$OUT/strace.log")
if strace --seccomp-bpf -e trace=none -o /dev/null true 2>/dev/null; then
  STRACE+=(--seccomp-bpf)
else
  echo "[!] 此 strace 不支持 --seccomp-bpf，wine 线程可能崩（Debian13 strace 5.x 支持）"
fi
if [ "$MODE" = mock ]; then
  CMD=(env "CANARY_FILE=$PRIMARY" "SINK_ADDR=$SINK:8080" "C2_HOST=c2.mock-example.top"
       "WINEPREFIX=$WINEPREFIX" "WINEDEBUG=$WINEDEBUG" "DISPLAY=" "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
       "${STRACE[@]}" "$WINE" "$HERE/mocktarget.exe")
else
  [ -f "$TARGET" ] || { echo "找不到 boot dll: $TARGET"; exit 1; }
  # 假 steam.exe 诱饵：3803426816 载荷按名枚举 steam.exe 并读其内存找 JWT——
  # 没有诱饵进程时这条窃密路径永远空跑、也到不了外传。
  # 诱饵必须与 harness 同在 bwrap 内（unshare-pid 下跨命名空间不可见）。
  # ⚠ 不能让 harness 进程自己 spawn（Go os/exec 在 Wine 下会卡死在 CreateProcess，
  # 实测 harness 主流程永远到不了 LoadLibrary）——由外层 shell 后台拉起，strace 只包
  # harness（诱饵是自家良性程序，不入轨迹），bwrap die-with-parent 负责收尸。
  RUNNER="'$WINE' '$HERE/harness.exe' '$TARGET' '$ORD'"
  DECOY_PRE=""
  # 默认不再并发拉起 steam.exe 诱饵进程：它只喂 ReadProcessMemory 取 JWT 这条路（离线窗口从未命中），
  # 却要在同一 wineprefix 里跑第二个 wine——低内存机（~900M）上两个 wine 抢同一 wineserver 会堆损坏
  # （decoy 与 harness 双双 free(): invalid pointer / Aborted，harness 到不了 LoadLibrary）。
  # 观察到的窃密行为（读 loginusers/localconfig、推导 userdata、写 steam.cfg/_local_patch_backup）
  # 全部来自 set-canaries 种下的 steam.exe/loginusers/steamui **文件**，不需要诱饵进程。
  # 需要 JWT 内存路径时用 SPAWN_DECOY_PROC=1 显式开启（建议只在内存充足的机器上）。
  if [ "${SPAWN_DECOY_PROC:-0}" = 1 ] && [ -n "$DECOY" ] && [ -n "$JWT_TOKEN" ]; then
    DECOY_PRE="STEAM_DECOY_TOKEN=$JWT_TOKEN WINEPREFIX='$WINEPREFIX' WINEDEBUG=- DISPLAY= '$WINE' '$DECOY' >'$OUT/decoy.out' 2>&1 & sleep 5; "
    echo "    (诱饵进程: $DECOY，JWT 金丝雀已注入；SPAWN_DECOY_PROC=1)"
  else
    echo "    (仅种 steam.exe 文件诱饵，不并发拉起诱饵进程；如需 JWT 内存路径设 SPAWN_DECOY_PROC=1)"
  fi
  # shellcheck disable=SC2016  — STRACE 引号在 -c 串内展开
  STRACE_STR=""
  for a in "${STRACE[@]}"; do STRACE_STR+="'${a//\'/\'\\\'\'}' "; done
  # pin 模式的沙箱内前置：拉起 lo（bwrap --unshare-net 的 lo 默认 DOWN）→ netns 内 sinkhole
  # （带 TLS MITM 证书）→ tcpdump。这些进程随 bwrap 的 pid-namespace 一起收尸；文件系统共享，
  # sink.jsonl/requests/capture.pcap 照常写进 $OUT。末尾 sleep 2 给 sinkhole 最后的落盘留时间。
  INNER_PRE=""
  if [ -n "$PIN" ]; then
    SARGS_STR=""
    for a in "${SARGS[@]}"; do SARGS_STR+="'${a//\'/\'\\\'\'}' "; done
    INNER_PRE="ip link set lo up 2>/dev/null || true; "
    INNER_PRE+="python3 '$SINKHOLE' $SARGS_STR >'$OUT/sinkhole.out' 2>&1 & echo \$! >'$OUT/sinkhole-inner.pid'; sleep 1; "
    if command -v tcpdump >/dev/null; then
      INNER_PRE+="tcpdump -i any -s 0 -w '$OUT/capture.pcap' >/dev/null 2>&1 & echo \$! >'$OUT/tcpdump-inner.pid'; "
    fi
  fi
  CMD=(env "WINEPREFIX=$WINEPREFIX" "WINEDEBUG=$WINEDEBUG" "DISPLAY=" "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
       bash -c "${INNER_PRE}${DECOY_PRE}${STRACE_STR}${RUNNER}; sleep 2")
fi
if [ "$ISOLATE" = 1 ] && command -v bwrap >/dev/null; then
  # --unshare-net 断网引爆：样本连不出去（防真连 C2/横向移动），
  # 但 strace 照样记录 connect()/sendto() 的目标地址与内容 → 外联地址与请求包仍完整可见。
  echo "    (bwrap 沙箱：私有 IPC/PID/UTS/网络断开，随父进程退出)"
  timeout "$SECONDS_RUN" bwrap --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
    --die-with-parent --new-session --dev-bind / / \
    "${CMD[@]}" >"$OUT/target.out" 2>&1 || true
else
  timeout "$SECONDS_RUN" "${CMD[@]}" >"$OUT/target.out" 2>&1 || true
fi

echo "[5/6] 停止采集..."
[ -f "$OUT/tcpdump.pid" ] && kill "$(cat "$OUT/tcpdump.pid")" 2>/dev/null || true
# pin 模式的 sinkhole/tcpdump 在沙箱 pid-ns 内，bwrap 退出时已随命名空间收尸，这里只停宿主侧的。
[ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
sleep 1
find "$WINEPREFIX/drive_c" -type f -printf '%p\t%s\n' 2>/dev/null | sort > "$OUT/files-after.txt" || true

echo "[6/6] 完成。分析：python3 $HERE/analyze-linux.py --run \"$OUT\" --canaries \"$OUT/canaries.txt\" --scanner ./vpetscan"
cat "$OUT/target.out" 2>/dev/null | tail -5
