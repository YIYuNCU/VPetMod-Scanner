<#
.SYNOPSIS
  汇总一次引爆的采集结果，按“必查项”逐条给出结论，输出 report.md。

.DESCRIPTION
  读取 Invoke-Detonation 产出的 procmon.csv / 快照 / capture.pcapng，以及 sinkhole.py 的 sink.jsonl，
  回答：
    A. 是否读取 Steam 登录凭证（金丝雀文件被访问）
    B. 是否外发/上传凭证（金丝雀令牌出现在网络流量里 = 铁证）
    C. C2 去向（DNS/SNI/HTTP 目的地）
    D. 是否动态下发/下载攻击载荷（HTTP GET + 新落地并执行的 PE）
    E. 是否持久化（自启动/服务/计划任务 diff）
    F. 子进程 / 可疑进程创建
  对新落地的 PE 会调用 vpetscan 复扫。

.EXAMPLE
  .\Analyze-Run.ps1 -RunDir run1 -Canaries canaries.txt.csv -Sink sink.jsonl -Scanner .\vpetscan.exe
#>
param(
  [Parameter(Mandatory)][string]$RunDir,
  [string]$Canaries = "canaries.txt.csv",
  [string]$Sink = "",
  [string]$Scanner = ""
)
$ErrorActionPreference = "Continue"
$RunDir = (Resolve-Path $RunDir).Path
$report = @()
function Add-Line($s) { $script:report += $s }

$canaryList = @()
if (Test-Path $Canaries) { $canaryList = Import-Csv $Canaries }
$tokens = $canaryList | ForEach-Object { $_.token }

# ---------- 读取 Procmon ----------
$csv = Join-Path $RunDir "procmon.csv"
$pm = @()
if (Test-Path $csv) { $pm = Import-Csv $csv }
$steamRe = 'ssfn|loginusers\.vdf|config\.vdf|SteamAppData|\\Steam\\config|wallet\.dat|Login Data|logins\.json|密码'

# ---------- 报告头 ----------
Add-Line "# VPet MOD 动态分析报告"
Add-Line ""
Add-Line "运行目录：``$RunDir``  生成时间：$(Get-Date -Format s)"
Add-Line "Procmon 事件：$($pm.Count)  金丝雀：$($canaryList.Count)"
Add-Line ""

# ========== A. 是否读取 Steam 凭证 ==========
Add-Line "## A. 是否读取 Steam / 凭证文件"
$credAccess = $pm | Where-Object { $_.Path -match $steamRe -and $_.Operation -match 'CreateFile|ReadFile|QueryOpen' }
if ($credAccess) {
  Add-Line "**命中**：进程访问了凭证相关文件（前 40 条）："
  Add-Line ""
  Add-Line "| 进程 | 操作 | 路径 | 结果 |"
  Add-Line "|---|---|---|---|"
  $credAccess | Select-Object -First 40 | ForEach-Object {
    Add-Line "| $($_.'Process Name') | $($_.Operation) | $($_.Path) | $($_.Result) |"
  }
} else {
  Add-Line "_未在 Procmon 中看到对凭证文件的读取。_ 注意：若样本用了直接系统调用或延迟触发，可能未覆盖到——以 B 项网络证据为准。"
}
Add-Line ""

# ========== B. 是否外发凭证（金丝雀令牌命中）==========
Add-Line "## B. 是否上传/外发凭证（金丝雀铁证）"
$hits = @()
# B1: sinkhole 日志里的 CANARY_EXFIL
if ($Sink -and (Test-Path $Sink)) {
  Get-Content $Sink | ForEach-Object {
    try { $o = $_ | ConvertFrom-Json } catch { return }
    if ($o.event -eq "CANARY_EXFIL") { $hits += "sinkhole: token=$($o.token) canary=$($o.canary) peer=$($o.peer) where=$($o.where)" }
  }
}
# B2: 直接在 pcap 里搜金丝雀令牌（即使没走我们的 sinkhole）
$pcap = Join-Path $RunDir "capture.pcapng"
if ((Test-Path $pcap) -and $tokens) {
  $bytes = [IO.File]::ReadAllBytes($pcap)
  $txt = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  foreach ($t in $tokens) {
    if ($txt.Contains($t)) {
      $lbl = ($canaryList | Where-Object token -eq $t).label
      $hits += "pcap: 抓包中出现金丝雀令牌 $t（$lbl）——数据确实离开了进程"
    }
  }
}
if ($hits) {
  Add-Line "**确认外发凭证（严重）**："
  $hits | ForEach-Object { Add-Line "- $_" }
} else {
  Add-Line "_未在网络流量中发现金丝雀令牌。_ 可能：未窃取；或加密后外发（令牌被加密则搜不到，需结合 C/D 项与 mitmproxy 明文）。"
}
Add-Line ""

# ========== C. 外链地址汇总（IP / 域名 / 端口）==========
Add-Line "## C. 外链地址汇总（IP / 域名 / 端口）"
$endpoints = New-Object System.Collections.Generic.List[object]
# C1: Procmon 的连接尝试（对端 IP:端口，即使连接被拒也记录，是最权威的外链清单）
$pm | Where-Object { $_.Operation -match 'TCP Connect|TCP Reconnect|UDP Send|UDP Receive' } | ForEach-Object {
  $dst = $_.Path
  if ($dst -match '->\s*(.+)$') { $dst = $matches[1].Trim() }   # "src:port -> dst:port" 取右侧
  $endpoints.Add([pscustomobject]@{ 目标 = $dst; 协议 = ($_.Operation -replace ' .*'); 来源 = 'Procmon'; 结果 = $_.Result })
}
# C2: sinkhole 的 DNS/SNI/对端
$dnsNames = @(); $sniNames = @()
if ($Sink -and (Test-Path $Sink)) {
  Get-Content $Sink | ForEach-Object {
    try { $o = $_ | ConvertFrom-Json } catch { return }
    switch ($o.event) {
      "DNS"     { $dnsNames += $o.qname; $endpoints.Add([pscustomobject]@{ 目标 = $o.qname; 协议 = 'DNS'; 来源 = "sinkhole/$($o.peer)"; 结果 = '' }) }
      "REQUEST" {
        $tgt = if ($o.proto -eq 'tls' -and $o.sni) { "$($o.sni):$($o.dport) (TLS)" }
        elseif ($o.proto -eq 'http') { "$($o.host):$($o.dport) (HTTP)" }
        else { "$($o.peer):$($o.dport) ($($o.proto))" }
        if ($o.sni) { $sniNames += $o.sni }
        $endpoints.Add([pscustomobject]@{ 目标 = $tgt; 协议 = $o.proto; 来源 = "sinkhole/$($o.peer)"; 结果 = '' })
      }
    }
  }
}
if ($endpoints.Count) {
  $uniq = $endpoints | Sort-Object 目标, 协议 -Unique
  Add-Line "| 目标(IP/域名:端口) | 协议 | 来源 | 结果 |"
  Add-Line "|---|---|---|---|"
  $uniq | ForEach-Object { Add-Line "| $($_.目标) | $($_.协议) | $($_.来源) | $($_.结果) |" }
  $uniq | Select-Object 目标, 协议, 来源, 结果 | Export-Csv (Join-Path $RunDir "endpoints.csv") -NoTypeInformation -Encoding UTF8
  Add-Line ""
  Add-Line "（完整清单另存 ``endpoints.csv``）"
} else {
  Add-Line "_未观察到任何外联尝试。_ 若为隔离网且样本靠 DNS 找 C2，请确认 VM 的 DNS 已指向 sinkhole；也可能有触发条件未命中。"
}
Add-Line ""

# ========== C2. 尝试发送的请求包 ==========
Add-Line "## C2. 尝试发送的请求包（完整内容）"
$reqs = @()
if ($Sink -and (Test-Path $Sink)) {
  Get-Content $Sink | ForEach-Object {
    try { $o = $_ | ConvertFrom-Json } catch { return }
    if ($o.event -eq "REQUEST") { $reqs += $o }
  }
}
if ($reqs) {
  Add-Line "共捕获 $($reqs.Count) 个外发请求（原始字节落盘在 sinkhole 的 requests/ 目录）："
  $i = 0
  foreach ($r in ($reqs | Select-Object -First 30)) {
    $i++
    Add-Line ""
    Add-Line "### 请求 #$i — $($r.proto) 到 $($r.peer):$($r.dport)  ($($r.total_bytes) 字节)"
    if ($r.host)    { Add-Line "- Host: $($r.host)" }
    if ($r.sni)     { Add-Line "- TLS SNI: $($r.sni)" }
    if ($r.request) { Add-Line "- 请求行: ``$($r.request)``" }
    if ($r.ua)      { Add-Line "- User-Agent: $($r.ua)" }
    if ($r.saved)   { Add-Line "- 原始字节文件: ``$($r.saved)``" }
    if ($r.hex) {
      Add-Line '```'
      ($r.hex -split "`n" | Select-Object -First 24) | ForEach-Object { Add-Line $_ }
      Add-Line '```'
    }
  }
} else {
  Add-Line "_未捕获到外发请求包。_ 常见原因：C2 用了非监听端口（看 §C 的 Procmon 端点，把该端口加进 sinkhole ``--extra-ports`` 再跑一次），或未触发外联。"
}
Add-Line ""

# ========== D. 动态下发/下载载荷 ==========
Add-Line "## D. 是否动态下发/下载攻击载荷"
$dl = @()
if ($Sink -and (Test-Path $Sink)) {
  Get-Content $Sink | ForEach-Object {
    try { $o = $_ | ConvertFrom-Json } catch { return }
    if ($o.event -eq "SERVED_PAYLOAD") { $dl += "样本发起下载：$($o.request)（我们回了诱饵 $($o.bytes) 字节）" }
    if ($o.event -eq "REQUEST" -and $o.proto -eq 'http' -and $o.request -match '^GET') { $dl += "GET $($o.host) :: $($o.request)" }
  }
}
# 落地的新 PE（快照 diff）+ 复扫
$before = Join-Path $RunDir "snapshot-before\files.csv"
$after = Join-Path $RunDir "snapshot-after\files.csv"
$dropped = @()
if ((Test-Path $before) -and (Test-Path $after)) {
  $b = @{}; Import-Csv $before | ForEach-Object { $b[$_.Path] = $_.Size }
  Import-Csv $after | ForEach-Object {
    if (-not $b.ContainsKey($_.Path) -or $b[$_.Path] -ne $_.Size) { $dropped += $_.Path }
  }
}
$newPE = $dropped | Where-Object { $_ -match '\.(exe|dll|scr|sys|tmp|dat)$' -and (Test-Path $_) } |
  Where-Object {
    try { $fs = [IO.File]::OpenRead($_); $mz = New-Object byte[] 2; [void]$fs.Read($mz, 0, 2); $fs.Close(); $mz[0] -eq 0x4D -and $mz[1] -eq 0x5A } catch { $false }
  }
if ($dl) { Add-Line "**下载/请求行为**："; $dl | Select-Object -First 30 | ForEach-Object { Add-Line "- $_" }; Add-Line "" }
if ($newPE) {
  Add-Line "**运行期间新落地的 PE 文件（疑似第二阶段载荷）**："
  foreach ($p in $newPE) {
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash
    Add-Line "- ``$p``  sha256=$sha"
    if ($Scanner -and (Test-Path $Scanner)) {
      $v = & $Scanner scan $p 2>&1 | Select-String -Pattern '^\[' | Select-Object -First 1
      if ($v) { Add-Line "  - vpetscan: $($v.Line.Trim())" }
    }
  }
} elseif (-not $dl) {
  Add-Line "_未观察到动态下载或新 PE 落地。_ 若 C2 未响应（隔离网），二阶段可能没被拉下来——建议用 sinkhole --serve 提供诱饵再跑一次。"
}
Add-Line ""

# ========== E. 持久化 ==========
Add-Line "## E. 是否建立持久化"
$persist = @()
foreach ($f in @("Run", "RunOnce")) {
  $bf = Get-ChildItem (Join-Path $RunDir "snapshot-before") -Filter "*$f*.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
  $af = Get-ChildItem (Join-Path $RunDir "snapshot-after") -Filter "*$f*.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($bf -and $af) {
    $d = Compare-Object (Get-Content $bf.FullName) (Get-Content $af.FullName) | Where-Object SideIndicator -eq '=>'
    if ($d) { $persist += "注册表 $f 新增：`n" + (($d.InputObject) -join "`n") }
  }
}
$sb = Join-Path $RunDir "snapshot-before\schtasks.txt"; $sa = Join-Path $RunDir "snapshot-after\schtasks.txt"
if ((Test-Path $sb) -and (Test-Path $sa)) {
  $d = Compare-Object (Get-Content $sb) (Get-Content $sa) | Where-Object SideIndicator -eq '=>'
  if ($d) { $persist += "计划任务出现变化（$($d.Count) 行差异，见快照）" }
}
$startupNew = $dropped | Where-Object { $_ -match 'Start Menu\\Programs\\Startup' }
if ($startupNew) { $persist += "启动文件夹新增：`n" + ($startupNew -join "`n") }
if ($persist) { $persist | ForEach-Object { Add-Line "- $_" } } else { Add-Line "_未发现自启动/服务/计划任务方面的持久化。_" }
Add-Line ""

# ========== F. 进程创建 ==========
Add-Line "## F. 进程创建"
$proc = $pm | Where-Object { $_.Operation -eq 'Process Create' } | Select-Object -ExpandProperty Detail -ErrorAction SilentlyContinue | Sort-Object -Unique
if ($proc) { $proc | Select-Object -First 40 | ForEach-Object { Add-Line "- $_" } } else { Add-Line "_无（或 Procmon 未捕获）。_" }
Add-Line ""

# ========== 结论 ==========
Add-Line "## 结论摘要"
Add-Line "- A 读取凭证：$(if($credAccess){'是'}else{'未观察到'})"
Add-Line "- B 外发凭证（金丝雀命中）：$(if($hits){'**是（铁证）**'}else{'未命中'})"
Add-Line "- D 动态下发载荷：$(if($dl -or $newPE){'是/疑似'}else{'未观察到'})"
Add-Line "- E 持久化：$(if($persist){'是'}else{'未观察到'})"
Add-Line ""
Add-Line "> 未观察到 ≠ 不存在：样本可能有触发条件（时间、特定 UI 操作、C2 指令）。建议多跑几轮、延长时长、并用 sinkhole --serve 诱导二阶段。"

$out = Join-Path $RunDir "report.md"
$report | Set-Content -Path $out -Encoding UTF8
Write-Host "[OK] 报告已生成：$out"
Get-Content $out | Select-Object -First 40
