#!/usr/bin/env bash
# 在 Wine 前缀内种植金丝雀凭证（Linux 版）。每个文件内嵌唯一令牌；令牌若出现在外发流量=窃密铁证。
# 用法: WINEPREFIX=/path/to/prefix ./set-canaries-linux.sh [canaries.txt]
#
# env（可选，由 detonate-linux.sh 传入）:
#   LOCALVDF_TOKEN  local.vdf 令牌（detonate 预生成并加密好后传入；缺省此处生成）。
#   LOCALVDF_BLOB   protectkey.exe 生成的 DPAPI hex blob，种进 local.vdf 的 ConnectCache。
#                   样本 CryptUnprotectData 成功后会拿到含令牌的明文——外发即铁证。
#                   缺省用占位 hex（解密会失败，但读取/尝试行为仍被 strace 记录）。
set -euo pipefail
: "${WINEPREFIX:?请设置 WINEPREFIX}"
OUT="${1:-canaries.txt}"
C="$WINEPREFIX/drive_c"
STEAM="$C/Program Files (x86)/Steam"
: > "$OUT"

plant() {  # plant <相对路径> <标签>
  local path="$1" label="$2" tok
  tok="CANARY-$(cat /proc/sys/kernel/random/uuid | tr -d - | tr 'a-z' 'A-Z')"
  mkdir -p "$(dirname "$path")"
  printf 'CanaryToken=%s\nlabel=%s\n%s\n' "$tok" "$label" "$(head -c 256 /dev/zero | tr '\0' A)" > "$path"
  printf '%s\t%s :: %s\n' "$tok" "$label" "$path" >> "$OUT"
  echo "[+] $label -> $path  token=$tok"
}

# vdf 格式诱饵：3803426816 的 plugin_8b 解析这些文件的条目结构（AccountName/ConnectCache），
# 纯文本"CanaryToken="行解析不出条目、样本拿不到数据——必须按真实 VDF 结构种，令牌编进字段值。
vdf_token() {  # vdf_token <标签>  → echo 令牌（已登记 canaries.txt）
  local label="$1" tok
  tok="CANARY-$(cat /proc/sys/kernel/random/uuid | tr -d - | tr 'a-z' 'A-Z')"
  printf '%s\t%s :: (vdf 字段值)\n' "$tok" "$label" >> "$OUT"
  echo "$tok"
}

mkdir -p "$STEAM/config" "$C/users/$USER/AppData/Local/Steam"

# ConnectCache 的 DPAPI blob（protectkey.exe 预生成传入；样本 CryptUnprotectData 能解开，
# 明文含令牌——被读走并入外传即铁证）。多个位置共用同一 blob/令牌；被哪个文件消费由 strace 路径区分。
BLOB="${LOCALVDF_BLOB:-01000000d08c9ddf0115d1118c7a00c04fc297eb01000000placeholder}"
T2="${LOCALVDF_TOKEN:-}"
if [ -z "$T2" ]; then T2=$(vdf_token steam-local-vdf); else
  printf '%s	steam-local-vdf :: (vdf 字段值)
' "$T2" >> "$OUT"; fi

# 1) loginusers.vdf：真实 VDF 结构，令牌编进 AccountName/PersonaName（样本会解析这两个字段），
#    并在账户块里放 ConnectCache（真实 Steam 的 ConnectCache 就在 loginusers.vdf 每账户下）。
T1=$(vdf_token steam-loginusers-vdf)
cat > "$STEAM/config/loginusers.vdf" <<EOF
"users"
{
	"76561197960287930"
	{
		"AccountName"		"canary_$T1"
		"PersonaName"		"Canary User $T1"
		"RememberPassword"	"1"
		"MostRecent"		"1"
		"Timestamp"		"1700000000"
		"ConnectCache"		"$BLOB"
		"connectcache"		"$BLOB"
	}
}
EOF
echo "[+] steam-loginusers-vdf -> $STEAM/config/loginusers.vdf  token=$T1（含 ConnectCache blob）"

# 2) local.vdf 的 ConnectCache
cat > "$C/users/$USER/AppData/Local/Steam/local.vdf" <<EOF
"Software"
{
	"Valve"
	{
		"Steam"
		{
			"AutoLoginUser"		"canary_$T2"
			"RememberPassword"	"1"
			"ConnectCache"
			{
				"76561197960287930"		"$BLOB"
			}
			"connectcache"
			{
				"76561197960287930"		"$BLOB"
			}
		}
	}
}
EOF
echo "[+] steam-local-vdf -> $C/.../Local/Steam/local.vdf  token=$T2"

# 2b) userdata/<accountID>/config/localconfig.vdf：plugin_8b 解析 loginusers 拿 SteamID →
#     换算 accountID(76561197960287930-76561197960265728=22202) → 构造该路径找凭据。
#     实测缺这个文件时凭据源全空、winhttp 根本不加载——外传分支不会发生。
ACCOUNTID=$((76561197960287930 - 76561197960265728))
mkdir -p "$STEAM/userdata/$ACCOUNTID/config"
for VDF in "$STEAM/userdata/$ACCOUNTID/config/localconfig.vdf" "$STEAM/config/localconfig.vdf"; do
  cat > "$VDF" <<EOF
"UserLocalConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"AutoLoginUser"		"canary_$T2"
				"RememberPassword"	"1"
				"ConnectCache"		"$BLOB"
				"connectcache"		"$BLOB"
			}
		}
	}
}
EOF
  echo "[+] localconfig.vdf -> $VDF（ConnectCache blob）"
done

# 2c) 预建样本自身的日志目录：plugin_8b 写 %LOCALAPPDATA%\..\LocalLow\guigugame\guigubahuang\px_mod.log，
#     CreateFileW(OPEN_ALWAYS) 不建父目录——缺目录=STATUS_OBJECT_PATH_NOT_FOUND，样本诊断日志哑巴。
#     建好目录后样本会把自己的运行结论（RPM 失败/凭据收集结果）写进日志，是最便宜的行为证据。
mkdir -p "$C/users/$USER/AppData/LocalLow/guigugame/guigubahuang"
echo "[+] 样本日志目录已预建（LocalLow/guigugame/guigubahuang，px_mod.log 可落地）"

# 3) steam.exe 文件诱饵：载荷会先 stat "Steam 安装目录/steam.exe" 判断 Steam 是否安装
#    （实测 ENOENT 时凭据提取提前放弃、连 loginusers.vdf 内容都不读）。种上 decoy 本体。
if [ -n "${STEAM_DECOY_EXE:-}" ] && [ -f "$STEAM_DECOY_EXE" ]; then
  cp -f "$STEAM_DECOY_EXE" "$STEAM/steam.exe"
  echo "[+] steam.exe 文件已种（$STEAM/steam.exe，加载它会铺 JWT 诱饵后常驻）"
fi

# 4) steamui 最小结构：assetplu8 要补丁真实存在的 steamui 资源（index.html/chunk~*.js/
#    webkit.css），全不存在时会反复重试拖满窗口，boot 串行处理导致后续凭据载荷没机会跑。
mkdir -p "$STEAM/steamui"
T4=$(vdf_token steamui-resource)
cat > "$STEAM/steamui/index.html" <<EOH
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Steam</title>
<link rel="stylesheet" href="webkit.css"></head>
<body><!-- canary $T4 --><div id="app"></div><script src="chunk~app.js"></script></body></html>
EOH
printf '/* steamui canary %s */
body{font-family:Arial}
' "$T4" > "$STEAM/steamui/webkit.css"
printf '/* chunk canary %s */ window.dispatchEvent(new Event("load"));
' "$T4" > "$STEAM/steamui/chunk~app.js"
echo "[+] steamui 最小结构已种（index.html/webkit.css/chunk~app.js，令牌 $T4）"

# 5) 其余路径无关条目解析，纯文件金丝雀即可
plant "$STEAM/config/config.vdf"      steam-config
plant "$STEAM/ssfn0000000000000001"   steam-ssfn
plant "$C/users/$USER/AppData/Roaming/Bitcoin/wallet.dat" btc-wallet
plant "$C/users/$USER/Desktop/密码备份.txt" desktop-passwords

# 6) 注册表 SteamPath（best effort）：样本可能经注册表定位 Steam 安装目录。
if command -v wine >/dev/null 2>&1 || command -v wine64 >/dev/null 2>&1; then
  W="$(command -v wine64 || command -v wine)"
  for KEY in 'HKLM\Software\Valve\Steam' 'HKLM\Software\Wow6432Node\Valve\Steam' 'HKCU\Software\Valve\Steam'; do
    WINEPREFIX="$WINEPREFIX" WINEDLLOVERRIDES="mscoree,mshtml=" "$W" reg add "$KEY" \
      /v SteamPath /t REG_SZ /d 'C:\Program Files (x86)\Steam' /f >/dev/null 2>&1 || true
  done
  echo "[+] 注册表 SteamPath 已种（Valve/Steam 三处）"
fi

# 7) 假 steam.exe 进程内的 JWT 金丝雀令牌：detonate 会以 STEAM_DECOY_TOKEN 注入诱饵进程。
T3=$(vdf_token steam-jwt-memory)
echo "$T3" > "${OUT}.jwttoken"
echo "[+] steam-jwt-memory -> 诱饵进程内存（令牌存 ${OUT}.jwttoken，供 detonate 注入）"

# 输出一个"主金丝雀"路径，供 mock 诱饵读取（真样本不需要）
echo "$STEAM/ssfn0000000000000001" > "${OUT}.primary"
echo "[OK] 种植完成 -> $OUT （主金丝雀路径见 ${OUT}.primary）"
