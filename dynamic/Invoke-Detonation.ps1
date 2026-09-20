<#
.SYNOPSIS
  在隔离 VM 里"引爆"一个可疑 VPet MOD，并全程采集文件/注册表/进程/网络行为。

.DESCRIPTION
  只在一次性快照虚拟机里运行（管理员）。流程：
    1) 采基线快照（自启动项/服务/计划任务 + 关键目录文件清单）
    2) 启动 pktmon 全量抓包（Windows 内置，无需装东西）
    3) 启动 Procmon 后台记录（需 Sysinternals Procmon.exe）
    4) 启动目标（VPet 主程序，或你指定的 -Launch 命令），跑 -Seconds 秒
    5) 停止采集，导出 pcapng / Procmon CSV，再采一次快照
  网络请配合 sinkhole.py：把 VM 的 DNS 指到本机，用 host-only 网卡，禁止 NAT 到真实互联网。

.PARAMETER Launch
  引爆命令。默认启动已订阅了可疑 MOD 的 VPet（需你在 VPet 里点“允许加载”以复现受害路径）。
  也可直接 -Launch '"C:\Program Files (x86)\Steam\steamapps\common\VPet\VPet.exe"'

.EXAMPLE
  .\Invoke-Detonation.ps1 -OutDir run1 -Seconds 180 -Procmon C:\tools\Procmon.exe `
     -Launch '"C:\Program Files (x86)\Steam\steamapps\common\VPet\VPet-Simulator.Windows.exe"'
#>
param(
  [string]$OutDir = "run-$(Get-Date -Format yyyyMMdd-HHmmss)",
  [int]$Seconds = 180,
  [string]$Procmon = "Procmon.exe",
  [string]$Launch = "",
  [string[]]$WatchDirs = @()
)
$ErrorActionPreference = "Continue"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Warning "需要管理员权限（pktmon/Procmon）。请以管理员身份重开 PowerShell。"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
Write-Host "[*] 输出目录: $OutDir"

if (-not $WatchDirs) {
  $WatchDirs = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData,
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
}

function Snapshot([string]$tag) {
  $d = Join-Path $OutDir "snapshot-$tag"; New-Item -ItemType Directory -Force -Path $d | Out-Null
  # 持久化位点
  foreach ($k in @(
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
      "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKLM:\SYSTEM\CurrentControlSet\Services")) {
    $safe = ($k -replace '[:\\]', '_')
    try { Get-ItemProperty $k -ErrorAction Stop | Out-String | Set-Content (Join-Path $d "$safe.txt") } catch {}
  }
  Get-Service | Select-Object Name, Status, StartType | Sort-Object Name |
    Out-String | Set-Content (Join-Path $d "services.txt")
  schtasks /query /fo LIST /v 2>$null | Set-Content (Join-Path $d "schtasks.txt")
  # 关键目录文件清单（含哈希，事后 diff 出新落地/被改的文件）
  $files = foreach ($wd in $WatchDirs) {
    if (Test-Path $wd) {
      Get-ChildItem -LiteralPath $wd -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object {
          [pscustomobject]@{ Path = $_.FullName; Size = $_.Length; Modified = $_.LastWriteTimeUtc }
        }
    }
  }
  $files | Export-Csv (Join-Path $d "files.csv") -NoTypeInformation -Encoding UTF8
  Write-Host "[*] 快照[$tag]: 文件 $($files.Count) 项"
}

Write-Host "[1/6] 采集基线快照..."
Snapshot "before"

$etl = Join-Path $OutDir "capture.etl"
$pcap = Join-Path $OutDir "capture.pcapng"
$pml = Join-Path $OutDir "procmon.pml"
$csv = Join-Path $OutDir "procmon.csv"

Write-Host "[2/6] 启动 pktmon 抓包..."
pktmon stop 2>$null | Out-Null
pktmon start --capture --pkt-size 0 --file $etl 2>&1 | Out-Null

$procmonOk = $true
Write-Host "[3/6] 启动 Procmon..."
try {
  Start-Process -FilePath $Procmon -ArgumentList @("/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", "`"$pml`"") -WindowStyle Hidden
  Start-Sleep -Seconds 2
} catch { $procmonOk = $false; Write-Warning "Procmon 启动失败（检查 -Procmon 路径）：$_" }

Write-Host "[4/6] 引爆目标，运行 $Seconds 秒..."
if ($Launch) {
  Write-Host "    Launch: $Launch"
  Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $Launch -WindowStyle Normal
} else {
  Write-Warning "未提供 -Launch：请手动启动已订阅可疑 MOD 的 VPet 并在其中点“允许加载”。"
}
1..$Seconds | ForEach-Object {
  Start-Sleep -Seconds 1
  if ($_ % 30 -eq 0) { Write-Host "    ...$_/$Seconds s" }
}

Write-Host "[5/6] 停止采集..."
if ($procmonOk) {
  Start-Process -FilePath $Procmon -ArgumentList @("/Terminate") -WindowStyle Hidden -Wait
  Start-Sleep -Seconds 2
  Write-Host "    导出 Procmon CSV..."
  Start-Process -FilePath $Procmon -ArgumentList @("/OpenLog", "`"$pml`"", "/SaveApplyFilter", "/SaveAs", "`"$csv`"") -WindowStyle Hidden -Wait
}
pktmon stop 2>&1 | Out-Null
Write-Host "    转换 pcapng..."
pktmon etl2pcap $etl --out $pcap 2>&1 | Out-Null

Write-Host "[6/6] 采集事后快照..."
Snapshot "after"

Write-Host ""
Write-Host "[OK] 采集完成：$OutDir"
Write-Host "     下一步：.\Analyze-Run.ps1 -RunDir `"$OutDir`" -Canaries canaries.txt.csv -Sink sink.jsonl -Scanner .\vpetscan.exe"
