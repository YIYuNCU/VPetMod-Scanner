# VPetMod-Scanner

针对 VPet 创意工坊 MOD 的恶意代码静态检测服务（Go，纯标准库）。只读字节、不加载也不执行被测文件。

首批规则来自 `Test/` 下捕获的 **PxBridge** 家族样本：

| 工坊条目 | MOD 名 / 作者 | 被替换的插件 | 形态 |
|---|---|---|---|
| 3803401951 | 刮刮卡 v1.0.4 / 步眠 | VPet.Plugin.ScratchCard.dll | 打包（boot + 两个加密载荷） |
| depot …3678898894967785038 | SmartPet / SMZ | SmartPet.dll | 打包 |
| depot …4637760495230589419 = **3803426816** | 天籁之音！/ 小铃铛·MadeSpark | VPet.Plugin.TianLaiZhiYin.dll | 打包 |
| 3792623130（鸭科夫假红信mod） | CF美国妞厚礼蟹 击杀音效 | 无（**跨游戏**投放：BepInEx/Unity 宿主） | **明态编译**（无 boot、无 overlay、导入表可读） |

> 天籁之音的工坊条目号已由另一位开发者的分析报告（《3803426816-完整静态安全分析报告》，native/ 共享目录）确认：其 native 三件套与桩的 SHA256 和本仓库 IOC 表逐字节一致。
>
> 鸭科夫那个包说明家族已经换过投放策略：同一个 C2 家族、第二套 C2 域名（`hhfyuxuz.top`）、宿主从 VPet 换成另一个游戏，载荷**不再加密**。纯结构规则（boot 尾部 / 载荷尾部 / 导出名 / 桩类型名）对它一条都不命中，抓它靠的是跨节的注入工件标记、裸 host 字节匹配、以及辅助程序集加载包内原生 DLL——见下面「规则」。

## 样本机理

```
VPet CoreMOD 枚举 plugin/*.dll（只扫顶层）
  └─ plugin/X.dll            7~9KB 加载器桩（MainPlugin 子类，类型在 SmartPet.PxBridge 命名空间）
       ├─ ThreadPool → LoadLibrary(native/<boot>.dll) → GetProcAddress(#1) → 调用
       │    └─ boot（导出名 boot_plain.dll）读自身 overlay：8B 密钥 + mod1 名 + mod2 名
       │          └─ 读取 native/<mod1>、<mod2>，BCrypt SHA256 派生密钥，解密后
       │             VirtualAlloc/VirtualProtect 手工映射执行（载荷的导入/导出表本身就是密文）
       └─ Assembly.LoadFrom / AssemblyLoadContext 加载 plugin/lib/X.orig.dll 并转发
            → 原 MOD 功能照常，用户察觉不到
```

- 注入器是 `prepare_vpet_mod.py`，上传用 `VpetOneClick.dll`（刮刮卡包里残留的 `upload_scratchcard.bat` 能看到），清单写在 `.px_sidecar`。
- **每次注入都会变形**：native DLL 的文件名随机，boot 只改末尾 44 字节 overlay，载荷重新加密 `.rdata/.data`。**整文件哈希每次都不一样，只靠哈希黑名单抓不住**，所以本工具主要靠结构特征（boot 主体哈希、`.text` 节哈希、导出名、overlay 格式、加载器桩类型名）。清空全部哈希 IOC 后样本仍判恶意，见测试 `TestSamplesDetectedWithoutHashes`。
- 但**明态编译**的新形态连"变形"这步都省了（鸭科夫包）：没有 overlay、没有 boot、`LoadLibrary` 走正常导入表，结构规则全部落空。所以补了两条与打包方式无关的规则：跨节注入工件标记（`PX-ARTIFACT-MARKERS`）、裸 host 字节匹配（`NET-KNOWN-C2`），再加一条针对跨程序集原生加载的 `GEN-HELPER-NATIVE-EXEC`。

### 已证实的载荷行为与 C2（3803426816 静态解密，另一位开发者完成）

两个加密载荷（assetplu8 = SteamUI 篡改、plugin_8b = 凭据窃取）已被独立解密分析（`decode_payloads.py`，未运行样本），恶意链全部坐实：

- **凭据窃取（plugin_8b）**：尝试启用 SeDebugPrivilege → 枚举 `steam.exe` → ReadProcessMemory 搜 JWT → 读 `config/loginusers.vdf` 与 `%LOCALAPPDATA%\Steam\local.vdf` 的 ConnectCache → `CryptUnprotectData`（DPAPI）解密 → JSON `{"i","t","o"}` 经 AES-CBC + Base64 组成表单 `d=...` → **WinHTTP POST 到 `https://bvdpp.top/ey/2.php`（内存 JWT）与 `/vdf/2.php`（本地凭据），443 端口**。
- **客户端篡改（assetplu8）**：定位 Steam 安装目录，改写 `steamui` 资源（`sp.js`、`chunk~*.js`、`index.html`、`webkit.css`，备份进 `_local_patch_backup`），插入 `<script defer src="/sp.js">`；注入 JS（`/*px:b*/…/*px:e*/`、`window.__pxH/__pxS/__pxPoll/__pxCM`）：轮询 `bvdpp.top/gate.php` 决定启用 → 3 秒轮询 `/api/messages` 伪造 Steam 通知与提示音 → 把帮助/支持页引到 `bvdpp.top/steamhelper*` 并拦截右键/复制、`clipboard.writeText` 写空。
- **规则联动**：`NET-KNOWN-C2`（critical）——任何被测文件**原始字节里**出现已知 C2 主机名（`bvdpp.top` / `hhfyuxuz.top`，子域名也算）直接判恶意。两种编码都查（ASCII 与 UTF-16LE），且**不要求 URL 形态**：载荷在磁盘上只存裸 host，URL 是运行时用 `https://%s/gate.php` 拼出来的，只匹配 `https?://` 的规则永远够不着（这条曾是本仓库 README 的一处假承诺，2026-09 评测发现后已修）。原始样本里 C2 在加密节内静态不可见；明文出现 = 新变种漏加密或配套投放物。动态侧 `analyze-linux.py` 命中这两个域名同样直接判 malicious 并在报告标注。
- **主机取证指标**（检查已运行过样本的机器）：`steamui/_local_patch_backup` 目录、资源里的 `/*px:b*/` 标记与 `sp.js` 引用、日志 `%LOCALAPPDATA%\..\LocalLow\guigugame\guigubahuang\px_mod.log`、对 `bvdpp.top` 的 DNS/连接记录。
- **动态坐实**（本仓库 Linux/Wine 引爆，见下）：喂饱诱饵后（假 `steam.exe`、真实结构的 `loginusers.vdf`/`local.vdf`、`steamui` 最小结构）载荷会解析我们种的 `loginusers.vdf`、提取 SteamID 换算 accountID 去找 `userdata/<id>/config/localconfig.vdf`（凭据侦察链），并落地 `_local_patch_backup/` + 写 `steam.cfg`（`BootStrapperInhibitAll=enable` 抑制自更新）。断网窗口内未触发到 `bvdpp.top` 的外传（离线 + Wine 下 ReadProcessMemory 取 JWT / gate.php 门控可能失败关闭）——外传能力由静态解密证实，两条路线互补。
- **未证实线索**（解密字符串里存在、执行链未确认）：`/download/2.zip` `/check.php?id=` `/downloadlog/`（疑似二阶段下载）；`ServiceAppMscopiAuto`、`ServiceApp360GuardLogon`、`_svc_launch.bat`、`360tray.exe`（疑似持久化/杀软对抗）；另有一批关联域名（skylinemediaworld.top 等 21 个）无当前样本通信证据，已进 `analyze-linux.py` 的观察名单（命中提示、不判恶意）。

## VPet 宿主侧的问题（建议反馈给 VPet 开发组）

见 `VPet/VPet-Simulator.Windows/Function/CoreMOD.cs`：

1. **"允许加载"按 MOD 名记录，不绑定文件哈希**（`Setting.passmod`，`IsPassMOD(Name)`）。用户允许过某个 MOD 后，作者推送的更新会直接加载新代码、不再提示；任何 MOD 只要在 `info.lps` 里冒用一个已被允许的 `vupmod` 名，就能继承这份信任。刮刮卡那个样本正是以"更新已有工坊条目"的方式投放的。
2. 验签用的是 `new X509Certificate2(file)`，它只取出嵌入的证书、**不校验签名是否有效**，文件改过也照样通过。`IsTrustedCertificate` 还只比较 Issuer 字符串。
3. 宿主只检查 `plugin/*.dll`，`native/`、`plugin/lib/` 等目录宿主完全不看，恶意代码可以放在这些地方。

## 构建与使用

```bash
go build -o vpetscan.exe .
go test ./...          # 样本测试默认读仓库上一级的 样本库/，可用 VPETSCAN_SAMPLES 覆盖
```

> 样本目录之前写死 `../../../Test`（不存在），于是 `go test ./...` 全绿但**所有样本断言都被 `t.Skip` 掉了** —— "改规则 → 跑测试"这条保护链是断的。现已改为真实路径 + `VPETSCAN_SAMPLES` 环境变量；目录不存在时才跳过。

### 命令行

```bash
vpetscan scan "C:\Program Files (x86)\Steam\steamapps\workshop\content\1920960"
vpetscan scan -json some_mod.zip plugin.dll
```

退出码：`0` 干净，`1` 可疑，`2` 恶意，`3` 出错。可以直接用在 CI 或上架审核脚本里。

### HTTP 服务（审核用）

```bash
vpetscan serve -listen 0.0.0.0:8740 -token <TOKEN> -data ./data \
  [-workers 2] [-max-upload-mb 256] [-allow-root <DIR>]... \
  [-auto-dynamic] [-dynamic-triggers malicious,suspicious,clean]
```

`-auto-dynamic`（默认关）：静态结论命中 `-dynamic-triggers`（默认 `malicious,suspicious,clean`）的任务**自动排入动态分析队列**，审核员全程只在网页操作，不需要任何人登录服务器跑分析。

> **为什么默认连 `clean` 也引爆**：静态"干净"只代表没命中已知结构特征——全新家族、只在 `DllMain` 里动手、或加密到静态看不出的载荷都可能是这种。所以只要样本里有**原生 PE**（能被 `LoadLibrary` 触发的代码），无论静态判什么都进动态复核一次；纯资源包 / 仅托管插件（没有原生 PE，本套原生 harness 无从引爆）会自动跳过、不浪费引爆。引爆目标优先级：`PX-BOOT-EXPORT`/`PX-BOOT-TRAILER` → `IOC-PE-BODY`/`PX-PAYLOAD` → `PX-JS-INJECT`/`PX-ARTIFACT-MARKERS`/`IOC-PE-TEXT`（明态载荷属于这一档）→ 兜底挑一个原生 PE（`native/` 目录下的 `.dll` 优先）。每次引爆用完即删（Wine 前缀 ~770M/次，worker `finally` 清理）。

上传后进入**异步任务队列**：接口立即返回任务 ID，后台 worker 扫描，结果与人工审核结论都持久化在 `-data` 目录（每个任务一个 JSON，审核动作追加到 `audit.jsonl`）。设置 `-token`（或环境变量 `VPETSCAN_TOKEN`）后，除 `/healthz` 和审核页面 `/` 外的接口都要带 `Authorization: Bearer <TOKEN>`。

支持的压缩包：**zip / 7z / rar / tar(.gz/.bz2/.xz)**，以及单个 DLL/EXE。压缩包最多展开 2 层嵌套。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 审核页面（拖拽上传、查看报告、通过/驳回），令牌在页面里填一次存本地 |
| GET | `/healthz` | 存活检查，不鉴权 |
| GET | `/api/v1/rules` | 规则清单 + 全部 IOC |
| POST | `/api/v1/scan` | 上传创建扫描任务。multipart `file` 字段或裸请求体（`?name=` 指定文件名）。参数：`submitter=` 提交者、`force=1` 跳过去重、`wait=<秒>` 同步等待结果（上限 120s） |
| GET | `/api/v1/tasks` | 任务列表，过滤 `state=` / `review=` / `verdict=`，分页 `limit=&offset=`（不含完整报告，只带结论摘要） |
| GET | `/api/v1/tasks/{id}` | 单任务完整信息（含报告） |
| POST | `/api/v1/tasks/{id}/review` | 人工裁决：`{"decision":"approved"\|"rejected","reviewer":"...","note":"..."}` |
| POST | `/api/v1/tasks/{id}/dynamic` | 回传**动态分析结果**（外联地址/请求包/凭证外发），挂到该任务，网页即显示 |
| POST | `/api/v1/dynamic?sha256=` | 同上，但按样本 SHA256 匹配任务（隔离环境不知道 task id 时用） |
| GET | `/api/v1/dynamic/next` | **动态分析 worker 认领**最旧的 pending 任务（返回 `task_id`/`target`/`filename`，队列空返 204）。认领即转 running，不会重复发放 |
| GET | `/api/v1/tasks/{id}/file` | 下载该任务的原始样本（worker 拿去引爆） |
| POST | `/api/v1/tasks/{id}/dynamic-error` | worker 回报基础设施故障（磁盘满/Wine 崩等）。**引爆没跑完 ≠ 没观察到行为**，故障必须显式标 error，绝不静默贴空报告 |
| GET | `/api/v1/audit` | 审核日志（倒序，`limit=`）：submit / scan_done / scan_error / approve / reject / dynamic |
| POST | `/api/v1/scan/path` | 同步扫描服务器本地路径，`{"path":"..."}`。**默认关闭**，需启动带 `-allow-root`，且只允许白名单目录内（先解析符号链接再比较） |

> **外联地址为什么静态扫描页看不到**：静态扫描（这台服务）只解析文件结构。PxBridge 类加密载荷的外联地址只在**动态引爆**时出现——服务开 `-auto-dynamic` 后全自动：静态判恶意/可疑 → 入队 → 装了 Wine 的隔离机上 `dynamic-worker.py` 轮询认领（`/dynamic/next`）→ 下载样本（`/tasks/{id}/file`）→ `detonate-linux.sh` 隔离引爆 → `analyze-linux.py --post` 回传 → 审核网页任务详情出现「🌐 外联地址 / 动态分析」板块（外联 IP/域名、请求包、金丝雀外发、读取的凭证文件、SteamUI 篡改落地）。任务列表带 🌐 = 已有动态结果，⏳ = 排队/进行中（网页 3 秒自动刷新）。
>
> **托管 .NET 插件的明文外联不需要动态分析**：静态扫描会直接提取并显示在「🔗 外联地址（静态提取）」板块（`report.network_indicators`），如 `NET-ENDPOINT`（URL/域名/IP）、`NET-EMBEDDED-SECRET`（`sk-`/`ghp_` 等内嵌密钥，页面显示打码值）与 `NET-KNOWN-C2`（已知 C2 主机名）。
>
> **原生 PE 同样会提取**（2026-09 起）：从 ASCII + UTF-16LE 字符串里抽 URL/IP/密钥，所以像 SMTC.exe 这类工具插件连的音乐接口（`y.qq.com`、`music.163.com`）也会列出来。这是**线索**不是定性（`NET-ENDPOINT` 只给 low=5 分），定性只看 `NET-KNOWN-C2` 或内嵌密钥。同一条 URL 不会再重复出现两次（URL 规则与裸字节规则命中同一 C2 时会去重）。

提交并同步等结果：

```bash
curl -H "Authorization: Bearer $T" -F file=@3803401951.zip "http://HOST:8740/api/v1/scan?wait=90&submitter=steam-bot"
```

返回结构（节选）：

```json
{
  "task": {
    "id": "tlm936-1", "filename": "3803401951.zip", "sha256": "...",
    "state": "done", "review": "pending", "created_at": "...",
    "report": {
      "target": "3803401951.zip", "verdict": "malicious", "score": 930,
      "mods": [{
        "root": "3803401951.zip!/3803401951", "name": "刮刮卡", "author": "步眠",
        "verdict": "malicious", "score": 930,
        "findings": [{
          "rule": "PX-BOOT-TRAILER", "severity": "critical", "title": "boot 加载器配置尾",
          "path": "3803401951.zip!/3803401951/native/asset_4g.dll",
          "detail": "将手工映射 gamev47.dll 与 msgame2.dll",
          "evidence": {"key": "63359d170bbe94eb", "mod1": "gamev47.dll", "mod2": "msgame2.dll"}
        }]
      }],
      "loose_findings": [], "pe_files": [...], "scanned_files": 42, "warnings": []
    }
  },
  "dedup": false
}
```

- 相同内容（SHA256 相同）再次上传会命中去重（`dedup:true`），直接返回上次的任务，不重复扫描；`force=1` 可强制重扫。
- 路径里的 `!` 表示进入压缩包内部。
- MOD 根目录 = 带 `vupmod#` 行的 `info.lps` 所在目录，与 VPet 自己的判定一致（动画目录里的 `info.lps` 不算 MOD 根）。**非 VPet 宿主**（Unity/BepInEx 风格，如鸭科夫包）的 `info.ini` 只要同时带 `name` 与 `publishedFileId`/`displayName`/`description` 之一，也认作 MOD 根，否则跨游戏样本会整包降级成 `loose_findings`、审核页看不到 MOD 名与作者。
- `loose_findings` 是不属于任何 MOD 的发现，例如单独上传的一个 DLL。
- 服务重启后任务与审核记录从 `-data` 目录恢复；重启时仍处于队列/扫描中的任务会被标记为 error，需重新提交。

### Docker 部署（离线 / Linux）

镜像基于 `FROM scratch`，`docker build` 不拉取任何镜像层，适合**无法访问 dockerhub 的机器**。二进制在有 Go 的机器上交叉编译（`CGO_ENABLED=0`，全静态），拷到目标机后目标机只做 build + run。

```bash
HOST=user@192.168.x.x TOKEN=your-secret ./deploy/deploy.sh
```

脚本会：交叉编译 → scp 二进制和 Dockerfile 到目标机 → `docker build`（离线）→ `docker run`（`-p 8740:8740`、`-v /opt/vpetscan/data:/data`、`--restart unless-stopped`）→ /dev/tcp 健康检查。可用环境变量：`PORT` `NAME` `DATA` `MAX_UPLOAD_MB` `SSH_OPTS`。

> 若目标机的 `docker` 需要 sudo，请把 `HOST` 用户加 sudoers 内免密，或改用 root。二进制在 COPY 进镜像前需有执行位（脚本在 Linux 上编译自带 +x；在 Windows 上编译则需 `chmod 0755` 后再 build）。Dockerfile `COPY` 的文件名是 `vpetscan-linux-amd64`——手动替换二进制时别传错名字，否则 build 出的是旧镜像（部署后核 `GET /api/v1/rules` 的规则数确认）。

## 动态分析流水线（Linux/Wine，全自动）

审核服务开 `-auto-dynamic` 后，命中触发结论（默认含 clean，见上）的任务自动进动态队列；隔离机上常驻一个 worker 即完成全部剩余工作，审核员只在网页上传和看结论：

```bash
# 隔离机（装 wine wine64 strace tcpdump bubblewrap；与审核服务同机也行，但在容器外）
cd linux && python3 dynamic-worker.py \
  --server http://127.0.0.1:8740 --token <TOKEN> \
  --sink 127.0.0.1 --isolate --seconds 60          # 常驻轮询
# 自检（不引爆真样本，用良性诱饵走通整条管线）：
python3 dynamic-worker.py --server ... --token ... --mock --once --seconds 20
```

流程：认领（`/dynamic/next`）→ 下载样本（`/tasks/{id}/file`）→ 解压定位 boot DLL → `detonate-linux.sh --isolate` 引爆 → `analyze-linux.py --post` 回传 → 网页显示。

- **`--isolate`（bwrap）**：私有 PID/IPC/UTS + **断网**（`--unshare-net`）+ 随父进程退出。断网防样本真连 C2 / 横向移动；`strace` 照样记录 `connect()`/`sendto()` 的目标地址与请求内容，外联地址与请求包仍完整可见。
- **采集面**：strace（`%file,%network,%process`，任意带路径系统调用）+ tcpdump + 自建 sinkhole（DNS/HTTP/TLS-SNI/裸 TCP + 请求落盘）+ 引爆前后 drive_c 文件快照（落地 PE 即二阶段证据）。
- **金丝雀铁证 + 诱饵**：引爆前在 Wine 前缀里种植假 Steam 凭证（真实 VDF 结构的 `loginusers.vdf`/`local.vdf`、`ssfn`、假钱包、假密码本），每个内嵌唯一 `CANARY-<uuid>` 令牌；令牌出现在任何外发流量里 = 窃密实锤（回答"是否上传 Steam 登录凭证"这个必查项）。为把只在真实环境才动手的窃密路径喂出来，还种假 `steam.exe`（内存铺金丝雀化 JWT）、`steamui` 最小结构、注册表 `SteamPath`，并用 `protectkey.exe`（DPAPI）生成可解的 `ConnectCache` blob。断网下 `sendto()` 内容里的令牌是唯一外发证据源，DNS 查询里的域名以明文长度前缀出现（`analyze-linux.py` 会还原并比对已知 C2）。
- **报告分项**：A 读凭证 / B 外发凭证(金丝雀) / C 外链地址 + C2 请求包 / D 动态下发载荷 / D2 SteamUI 篡改落地(`steam.cfg`、`_local_patch_backup`) / E 持久化 / F 子进程。命中已知 C2、金丝雀外发或 SteamUI 篡改任一项即判 malicious。
- **工作目录**：默认 `/var/tmp/vpetdyn`（可用 `--work-dir` 改）。**不要**用 `/tmp`——Wine 前缀单次 400MB+，`/tmp` 常是几百 M 的 tmpfs 会被撑爆，引爆脚本写到一半失败。
- 引爆脚本早退（磁盘满、Wine 崩）时 worker 回报 `dynamic-error`，任务在网页上显示 ⚠ 失败原因，而不是"分析完成但什么都没看到"。
- `--mock` 的数据（`c2.mock-example.top` 等诱饵域名）只用于验证管线，**不会**作为真实结论展示给审核员——真跑请去掉 `--mock`。

> **strace × wine 崩溃坑**：`strace -f`（跟随线程）会让 wine 无 preloader 布局页错误崩溃，boot 链根本跑不起来。detonate-linux.sh 已用 `--seccomp-bpf`（只在被过滤 syscall 上 ptrace-stop）规避，并带能力探测 fallback（Debian13 strace 5.x 支持）。

## 判定

每条规则有一个严重级别：critical=100、high=40、medium=15、low=5。在同一个 MOD 内，同一条规则只计一次分。

- 命中任意一条 critical → **恶意**
- 总分 ≥ 80 → **恶意**
- 总分 ≥ 30 → **可疑**
- 其余 → **干净**

整体结论取风险最高的那个 MOD，不把各 MOD 的分数相加。完整规则见 `internal/scan/rules.go` 或 `GET /api/v1/rules`。

### 与打包方式无关的四条规则（2026-09 增加）

前三条针对**明态编译**载荷——这类样本没有任何加密/加壳结构可用，只能看内容：

| 规则 | 级别 | 判定条件 | 说明 |
|---|---|---|---|
| `PX-ARTIFACT-MARKERS` | critical | 同一文件**任意节**命中 ≥3 个家族标记，且至少 1 个是强标记 | 标记分强弱两档：强标记是注入器自有命名（`/*px:b*/`、`/*px:e*/`、`_local_patch_backup`、`px_msgpoll.js`、`[SteamUI sp]`、`m_nUnviewedNotifications`、`desktop_toast_default.wav`、`px_mod.log`）；弱标记（`/gate.php`、`/steamhelper`、`api/messages`、`ConnectCache`）正常 Steam 生态也可能有。ASCII 与 UTF-16LE 两种编码都查。**只搜 `.text` 会整体漏掉**——明态载荷把这些标记放在 `.rdata`。 |
| `PX-ARTIFACT-MARKERS-WEAK` | low | 命中 1~2 个，或只命中弱标记 | 仅线索，不足以定性（单独出现只加 5 分，判不出可疑）。 |
| `NET-KNOWN-C2`（强化） | critical | **原始字节**里出现已知 C2 主机名 | 不再要求 `https?://` 形态，不再限于托管 `#US` 堆：ASCII + UTF-16LE 直接子串匹配，覆盖"只存裸 host + 运行时拼 URL"的真实载荷形态。 |
| `GEN-HELPER-NATIVE-EXEC` | medium | **非** `MainPlugin` 入口的托管程序集引用原生加载三件套，且按名加载的 `*.dll` **能在本包内解析到** | 真正干活的 native DLL 由辅助程序集按名加载（鸭科夫包 `CalcBridge.dll` → `SteamCFyinxiao.dll`，同包内）。原先在 `MainPlugin` 检查之后提前 `return`，整条链一条发现都没有。**"包内可解析"这个条件是必须的**：合法库同样引用这三件套并指名 DLL（`CSCore.dll` → `X3DAudio1_7.dll`、`Microsoft.CodeAnalysis.dll` → `Microsoft.DiaSymReader.Native.x86.dll`、`System.Management.dll` → `wminet_utils.dll`），但它们加载的是系统/旁加载组件，不在包内。 |

误报控制（工坊语料回归，见下）：`PX-ARTIFACT-MARKERS` 只命中家族载荷（以及 3803401951 包里作者自己带的静态分析产物文本——那些文件确实含标记串，属真阳）；`GEN-HELPER-NATIVE-EXEC` 在 134 个正常 MOD 上零命中。

> **一条已删除的规则，别再想当然加回来**：曾经有过 `PX-PACKER-FPTABLE`（"全零 `.fptable` 节 = 打包器占位节"）。**这个判断是错的。** `.fptable` 是 Universal CRT 的函数指针缓存节——`ucrt/internal/winapi_thunks.cpp` 里 `#pragma data_seg(push, almostro, ".fptable")` + `#pragma bss_seg(...)` 放了一个 `static void* function_pointers[]`；Windows SDK ≥ 10.0.26100 起任何链接 UCRT 的 PE 都会带它，因为是 `bss_seg` 所以内容全零、`raw_size` 一页对齐（0x200）、`virt_size` = 指针数×指针宽度（x64 32×8=0x100，x86 32×4=0x80）。家族组件确实也带，但那只能说明它们同样是新 SDK 编的，**与家族归属无关**。工坊 134 MOD 回归实测：3 个正常 MOD 的 `VPetLLM.SecureCommunication.dll` 命中，并把其中一个从 clean(20) 抬到 suspicious(35)。规则已删除，并在 `scan_test.go` 留了 `TestFptableIsNotARule` 防回归。

### 误报基线（工坊语料回归）

2026-09 实测 `G:\steamlibrary\steamapps\workshop\content\1920960`：**134 个 MOD、22244 个文件、322 个 PE**，打补丁前后**全部 134 个判干净**，零误报、零判定变化。

本轮回归还顺带修掉了三类新增噪声（都不影响判定，只影响审核页可读性）：

| 噪声 | 来源 | 处理 |
|---|---|---|
| `crl.microsoft.com/pkiops/...` ×12/文件 | 签名 PE 的 Authenticode 证书链 | 字符串提取整块跳过证书表（`Info.CertOffset`） |
| `w3.org/2000/xmlns/`、`james.newtonking.com/...` 等 | XML 命名空间 / 文档标识符 | host 白名单式过滤（`uriOnlyHosts`）；已知 C2 判定在其之前，不受影响 |
| `4.0.0.0`、`1.3.6.1`、`2.5.4.15` | 程序集版本号、ASN.1 OID 片段 | 原生 PE 不再抽裸 IP；`x.y.0.0` 网络地址与"更长点分数字串的一截"都判为非 IP |

> 上面三点都只作用于 `NET-ENDPOINT`（low=5 分，且同一 MOD 内只计一次），**判定阈值不受影响**。原生 PE 仍然会抽 URL，所以像 `SMTC.exe` 连 `y.qq.com`/`music.163.com`、`VPet.Plugin.LLMEP.dll` 连 `api.openai.com`/`localhost:11434` 这类**真实情报照常显示**。

## 限额

单文件 64MB，单次扫描累计读入 1GB，最多 50000 个文件。zip 条目按实际解压的字节数截断，不信 zip 头里声明的大小。超限的文件会被跳过，并在 `warnings` 里记一条，不会中断整次扫描。

## 新增样本时

1. 把新样本的整文件 SHA256 加进 `iocFileSHA256`。如果是新的 boot 或载荷构建，再把去掉 overlay 后的主体哈希和 `.text` 节哈希分别加进 `iocBodySHA256` / `iocTextSHA256`（rules.go）。
2. 在 `TestSamplesDetectedWithoutHashes` 里确认新样本不靠哈希也能检出。如果检不出，说明家族有了新变化，需要补结构规则。
3. 新的 C2 域名要**同时**加三处，漏一处就会出现"静态判恶意、动态报告却说没连已知 C2"的割裂：
   - `internal/scan/rules.go` 的 `knownC2Hosts`（静态字节匹配）
   - `linux/analyze-linux.py` 的 `KNOWN_C2`（动态报告定性）
   - `linux/dynamic-worker.py` 的 `--pin-c2` 默认值（隔离机 hosts 钉住 + TLS MITM 抓包）
4. 新发现的高区分度标记串加进 `rules.go` 的 `pxArtifactStrong`；只有"正常生态里也可能出现"的才放 `pxArtifactWeak`（弱标记凑不满 3 个是不能定性的）。
5. 补一条回归：把样本放进 `样本库/`（或用 `VPETSCAN_SAMPLES` 指过去）后跑 `go test ./...`，确认样本用例**真的执行**而不是 `t.Skip`。变种（抹掉单个标记、破坏尾部、改名）也要各补一条——`TestPlaintextPayloadWithoutGateMarker` 就是这类用例的样板。
6. **任何新规则都要先过工坊语料回归**（`_analysis/vpetscan_port/scan_workshop.py`，只读静态扫描，不执行样本）：`python scan_workshop.py` 会对 134 个 MOD 逐个跑并列出判定变化与新规则命中。加规则最大的风险不是漏报而是误报——`.fptable` 那条就是这么被证伪的（一个"看起来极像指纹"的编译产物把 3 个正常 MOD 判成可疑）。
