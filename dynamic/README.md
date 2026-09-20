# VPet MOD 动态分析工具包

在**隔离虚拟机**里引爆一个可疑 VPet MOD，查清它到底做了什么——重点回答两个严重问题：

- **是否窃取并上传 Steam 登录凭证？**
- **是否动态下发 / 下载攻击载荷（第二阶段）？**

配套的静态扫描器（`../`，`vpetscan`）负责上架前拦截；本工具包负责**定性**：搞清楚被拦下的样本实际行为。

> ⚠️ 只在一次性、带快照、可回滚的隔离虚拟机里操作。网络用 host-only，**绝不 NAT 到真实互联网**。不要在装有真实 Steam / 浏览器 / 钱包账号的机器上运行——`Set-Canaries.ps1` 会覆盖真实凭证文件（已自动备份，但仍请用干净 VM）。

## 必查项 → 工具怎么回答

| # | 必查项 | 判定依据 | 由谁给出 |
|---|---|---|---|
| A | 是否读取 Steam / 凭证文件 | Procmon 里对 `ssfn*`/`loginusers.vdf`/`config.vdf`/钱包/浏览器登录库的 CreateFile/ReadFile | Analyze-Run §A |
| B | **是否上传凭证** | **金丝雀令牌出现在外发流量里**（sinkhole 请求体 或 pcap 明文）——铁证 | Analyze-Run §B |
| C | **外链地址（IP/域名:端口）** | Procmon 的每个 TCP/UDP 连接尝试（对端，含被拒的）＋ sinkhole 的 DNS/SNI/HTTP Host；汇总成表并另存 `endpoints.csv` | Analyze-Run §C |
| C2 | **尝试发送的请求包（完整内容）** | sinkhole 把每个外发请求的**原始字节**落盘到 `requests/`，报告里列出请求行/Host/UA + 十六进制转储 | Analyze-Run §C2 |
| D | **是否动态下发/下载载荷** | sinkhole 收到 GET 请求（可回诱饵观察完整链路）＋运行期间新落地并可执行的 PE（自动用 vpetscan 复扫） | Analyze-Run §D |
| E | 是否持久化 | Run/RunOnce、服务、计划任务、启动文件夹的前后 diff | Analyze-Run §E |
| F | 子进程 | Procmon 的 Process Create | Analyze-Run §F |

> **抓全外链端口的技巧**：sinkhole 默认监听 80/8080/443（HTTP/TLS）。若 §C 显示样本连的是别的端口（如自建 C2 用 14444），把该端口加进 `--extra-ports 14444,4444,...` 再跑一次——裸 TCP 监听会把该端口的**完整请求包**也抓下来。Procmon 无论哪个端口都会记录连接尝试，所以外链 IP 清单不会漏，只是要补监听才能拿到该端口的请求内容。

**金丝雀（canary）机制是 B 项的核心**：往真实凭证路径写入内嵌唯一随机令牌的假文件；样本若窃取并回传，令牌就会出现在网络流量里。令牌是明文外发→直接命中；若样本加密后外发，令牌搜不到，此时结合 C（C2 域名）+ D（数据量/mitmproxy 明文）判断。

## 准备（在隔离 VM 内，一次）

1. Windows 10/11 虚拟机，拍一个干净快照。**host-only 网卡**，无 NAT。
2. 装 [Sysinternals Procmon](https://learn.microsoft.com/sysinternals/downloads/procmon)（单 exe，拷进去即可）。Python 3、pktmon 走 Windows 内置。
3. 拷入本目录全部脚本、`vpetscan.exe`（静态扫描器）、以及要分析的可疑 MOD。
4. 让 VPet 订阅/放置该 MOD。VPet 默认不加载未签名插件，分析时**要手动点“允许加载”**——这正是复现受害者的操作路径。

## 运行（四步）

```powershell
# 1) 种植金丝雀凭证（覆盖真实路径，自动备份到 .\canary-backup\）
.\Set-Canaries.ps1 -OutFile canaries.txt

# 2) 起 sinkhole（另开一个管理员窗口，保持运行）。--ip 填本 VM 的 host-only 地址；
#    把 VM 的 DNS 也指到本机(127.0.0.1)；防火墙放行入站 UDP53/TCP80/TCP443。
#    --serve 提供一个诱饵文件，用来观察“动态下载载荷”的完整链路。
python sinkhole.py --ip 10.0.0.1 --log sink.jsonl --canary-file canaries.txt --serve decoy.bin

# 3) 引爆并采集（管理员）。-Launch 指向 VPet，或先手动开 VPet 再用默认。
.\Invoke-Detonation.ps1 -OutDir run1 -Seconds 180 -Procmon C:\tools\Procmon.exe `
   -Launch '"C:\Program Files (x86)\Steam\steamapps\common\VPet\VPet-Simulator.Windows.exe"'
#    运行期间在 VPet 里正常互动、点“允许加载”该 MOD，尽量触发其功能。

# 4) 出报告
.\Analyze-Run.ps1 -RunDir run1 -Canaries canaries.txt.csv -Sink sink.jsonl -Scanner .\vpetscan.exe
#    结果见 run1\report.md
```

## 组件

| 文件 | 作用 |
|---|---|
| `Set-Canaries.ps1` | 种植带令牌的金丝雀凭证（Steam ssfn/loginusers/config、浏览器登录库、钱包、桌面密码），生成 `canaries.txt` 与 `.csv` 清单 |
| `sinkhole.py` | 纯标准库 DNS + HTTP(80/8080) + TLS-SNI(443) 汇聚点；记录 C2 域名、HTTP 请求、外发数据；命中金丝雀即报 `CANARY_EXFIL`；`--serve` 对 GET 回诱饵以观察下载链路 |
| `Invoke-Detonation.ps1` | 采基线快照 → pktmon 抓包 + Procmon 记录 → 引爆 → 停止 → 事后快照 |
| `Analyze-Run.ps1` | 汇总以上产物，按必查项 A–F 出 `report.md`，对新落地 PE 调 `vpetscan` 复扫 |

## 结果判读

- **B 项命中金丝雀 = 确认窃取上传凭证**，无需再争论。报告会给出令牌、对应哪个凭证文件、发往的对端。
- **C 项的域名/IP** 就是 C2，可直接拉黑、上报、作为 IOC 补进 `vpetscan` 规则。
- **D 项**：sinkhole 收到 GET＝样本在拉第二阶段；报告里新落地的 PE 就是落盘的载荷，已自动复扫并给出 sha256。
- **“未观察到”不等于“没有”**：样本常有触发条件（等待若干分钟、特定聊天/点击、C2 下指令才行动）。建议：延长 `-Seconds`、多跑几轮、务必开 `--serve` 诱导二阶段、必要时上 mitmproxy 看 TLS 明文。

## 想看 TLS 明文（可选）

本工具只从 ClientHello 取 SNI（域名），不解密。若要看 HTTPS 里的请求体/回包（例如确认加密外发的具体内容、或 C2 下发的指令），在 VM 内装 [mitmproxy](https://mitmproxy.org/)，把它的 CA 导入系统信任，将 80/443 指向 mitmproxy，再把 mitmproxy 上游指到 sinkhole。这样金丝雀即使经 TLS 外发也能在 mitmproxy 流量里看到。
