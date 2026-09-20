<#
.SYNOPSIS
  在隔离 VM 里种植"金丝雀"凭证文件：Steam 登录态 + 常见被盗目标。
  每个文件内嵌一个唯一随机令牌。之后只要该令牌出现在外发流量(sinkhole/pcap)里，
  即证明样本读取并回传了该凭证——这是"是否上传 Steam 登录凭证"的判定核心。

.DESCRIPTION
  仅在一次性隔离虚拟机中运行。不要在装有真实 Steam 账号的机器上运行——它会覆盖真实凭证文件。
  脚本会：
    1) 备份将被覆盖的真实文件到 .\canary-backup\
    2) 写入带令牌的假文件到 Steam / 浏览器 / 加密货币等常见路径
    3) 生成 canaries.txt（token<TAB>标签）供 sinkhole.py 与 Analyze-Run.ps1 使用

.EXAMPLE
  .\Set-Canaries.ps1 -OutFile canaries.txt
#>
param(
  [string]$OutFile = "canaries.txt",
  [string]$SteamPath = "C:\Program Files (x86)\Steam"
)
$ErrorActionPreference = "Stop"
$backup = Join-Path (Get-Location) "canary-backup"
New-Item -ItemType Directory -Force -Path $backup | Out-Null
$manifest = @()

function New-Token { "CANARY-" + ([guid]::NewGuid().ToString("N")).ToUpper() }

function Plant([string]$Path, [string]$Label, [scriptblock]$Content) {
  $tok = New-Token
  $dir = Split-Path $Path -Parent
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  if (Test-Path $Path) {
    Copy-Item $Path (Join-Path $backup ([IO.Path]::GetFileName($Path) + "." + [guid]::NewGuid().ToString("N").Substring(0,6) + ".bak")) -Force
  }
  $body = & $Content $tok
  if ($body -is [byte[]]) { [IO.File]::WriteAllBytes($Path, $body) }
  else { [IO.File]::WriteAllText($Path, $body, [Text.UTF8Encoding]::new($false)) }
  $script:manifest += [pscustomobject]@{ token = $tok; label = $Label; path = $Path }
  Write-Host ("[+] {0,-22} {1}  token={2}" -f $Label, $Path, $tok)
}

# ---- Steam 登录态相关（窃密木马最常翻的几处）----
# loginusers.vdf：记录已登录账号与 SteamID
Plant "$SteamPath\config\loginusers.vdf" "steam-loginusers" {
  param($t)
@"
"users"
{
    "76561198000000001"
    {
        "AccountName"      "canary_victim"
        "PersonaName"      "canary_victim"
        "RememberPassword" "1"
        "MostRecent"       "1"
        "Timestamp"        "1700000000"
        "CanaryToken"      "$t"
    }
}
"@
}
# config.vdf：包含连接信息、有时含敏感字段
Plant "$SteamPath\config\config.vdf" "steam-config" {
  param($t)
@"
"InstallConfigStore"
{
    "Software"
    {
        "Valve"
        {
            "Steam"
            {
                "CanaryToken" "$t"
            }
        }
    }
}
"@
}
# ssfn*：Steam 记住登录的哨兵文件（二进制，木马常整文件回传）
Plant "$SteamPath\ssfn0000000000000001" "steam-ssfn" {
  param($t)
  [Text.Encoding]::ASCII.GetBytes("SSFN-CANARY-$t-" + ("A"*512))
}
# Steam MobileAuth / 令牌缓存目录里的示例
Plant "$SteamPath\config\SteamAppData.vdf" "steam-appdata" {
  param($t) "`"SteamAppData`"{ `"CanaryToken`" `"$t`" }"
}

# ---- 浏览器登录数据（顺带覆盖，很多 stealer 一起偷）----
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
Plant "$chrome\Login Data" "chrome-logindata" { param($t) [Text.Encoding]::ASCII.GetBytes("SQLite format 3`0CANARY-$t") }
Plant "$env:APPDATA\Mozilla\Firefox\Profiles\canary.default\logins.json" "firefox-logins" {
  param($t) "{`"logins`":[{`"hostname`":`"https://canary.example`",`"encryptedPassword`":`"$t`"}]}"
}

# ---- 加密钱包（勒索/窃密常见目标）----
Plant "$env:APPDATA\Bitcoin\wallet.dat" "btc-wallet" { param($t) [Text.Encoding]::ASCII.GetBytes("WALLET-CANARY-$t") }

# ---- 通用诱饵：桌面上的"密码.txt"----
Plant "$env:USERPROFILE\Desktop\密码备份.txt" "desktop-passwords" {
  param($t) "网银密码: hunter2`nSteam: canary_victim / $t`n"
}

# 写出清单
$manifest | ForEach-Object { "$($_.token)`t$($_.label) :: $($_.path)" } | Set-Content -Path $OutFile -Encoding UTF8
$manifest | Export-Csv -Path ($OutFile + ".csv") -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "[OK] 种植 $($manifest.Count) 个金丝雀 -> $OutFile （原文件已备份到 $backup）"
Write-Host "     把 $OutFile 传给 sinkhole.py --canary-file，把 .csv 传给 Analyze-Run.ps1"
