# VPet MOD 动态分析工具包（Linux / Wine）

在**资源有限的 Linux 服务器**上动态引爆可疑 VPet MOD，回答同一组必查项（读凭证 / 外发凭证 / 外链地址 / 请求包 / 动态载荷 / 持久化 / 子进程）。面向没有 Windows 也没有嵌套虚拟化的部署环境。

## 为什么用 Wine 而不是虚拟机
样本是 Windows PE（原生 x64 载荷 + .NET 桩）。要动态观察它就得在 Windows 语义下执行：

- 测试机实测 **无 KVM / 无 vmx-svm**（本身是台 VM，嵌套虚拟化关闭）→ 跑不了 Windows 客户机。
- 内存仅 ~900MB → 也扛不住一个 Windows 虚拟机。
- **Wine 是唯一可行路径**，而且轻：不跑完整 VPet(WPF)，只用一个最小原生 `harness` 直接触发 boot 加载链——真正的联网/读文件/解密行为都在 boot 和载荷里。

已在 Debian 13 + Wine 10.0 上跑通（`apt-get install wine64 strace tcpdump`，全部来自官方源，无需外网镜像）。

## ⚠️ 隔离与安全（必读）
**Wine 不是安全边界**——原生载荷在 Wine 下就是真在你的 Linux 上跑。所以真样本务必：

1. **在可回滚快照的一次性主机上跑**（这台机本身是 VM，跑前拍快照，跑完回滚就是最好的兜底）。
2. 用 `--isolate`（bwrap 命名空间）+ **网络只放行 sinkhole**（把默认路由去掉，DNS 指向 sinkhole）。
3. **不要**在生产机 / 有真实账号的机器上跑真样本。
4. 不要和静态扫描服务同时跑——900MB 内存同时跑 Wine+抓包会紧张，分时进行。

为"验证可行性"，本包带一个**良性诱饵** `mocktarget.exe`（行为等价于窃密：读金丝雀→回连 sinkhole→回传令牌），用它跑通流水线不会引爆真恶意代码。

## 组件
| 文件 | 作用 |
|---|---|
| `harness.exe` | win64 最小加载器：`LoadLibrary(boot)` + 按序号调用，复现 .NET 桩触发 boot 的动作（真样本用） |
| `mocktarget.exe` | **良性**诱饵，验证流水线用 |
| `set-canaries-linux.sh` | 在 Wine 前缀内种植带唯一令牌的金丝雀凭证（Steam ssfn/loginusers/config、钱包、桌面密码） |
| `detonate-linux.sh` | 编排：初始化前缀 → 种金丝雀 → 起 sinkhole + tcpdump → strace 引爆 → 前后快照 |
| `analyze-linux.py` | 汇总 strace/pcap/sinkhole → `report.md`（A–F + 外链表 + 请求包），对落地 PE 调 `vpetscan` 复扫 |
| `../dynamic/sinkhole.py` | 复用同一个 DNS+HTTP+TLS-SNI+裸TCP 汇聚点（纯标准库） |

## 依赖
```bash
sudo apt-get install -y wine64 strace tcpdump   # Debian/Ubuntu；wine 需 win64 前缀，脚本已设 WINEARCH=win64
# harness.exe / mocktarget.exe 在有 Go 的机器上交叉编译（见 src/，GOOS=windows GOARCH=amd64），拷过来即可
```

## 用法
```bash
# 1) 验证可行性（安全，良性诱饵跑完整流水线）
bash detonate-linux.sh --mock --sink 127.0.0.1 --seconds 20 --out mockrun
python3 analyze-linux.py --run mockrun          # 看 mockrun/report.md

# 2) 真样本（务必先快照 + 隔离）
#    先把可疑 MOD 拷进来，找到 native/ 下的 boot dll（.px_sidecar 的 boot= 字段，或用 vpetscan 报告里的 PX-BOOT-EXPORT）
sudo bash detonate-linux.sh --boot /samples/mod/native/helper_5e.dll \
     --sink 10.7.0.1 --isolate --serve decoy.bin --seconds 180 --out run1
python3 analyze-linux.py --run run1 --scanner ./vpetscan

# 3) 回传到审核网页（外联地址/请求包就会显示在对应任务的「🌐 外联地址 / 动态分析」板块）
python3 analyze-linux.py --run run1 \
     --post http://审核服务:8740 --token <TOKEN> --task <任务ID>
#   不知道任务 ID 时用 --sha256 <样本SHA256> 让服务端按哈希匹配
```

回传后：审核网页任务列表该任务带 🌐 标记，详情页出现外联地址表、请求包十六进制、金丝雀外发、读取的凭证文件。`analyze-linux.py` 也会在 run 目录生成 `dynamic.json`（回传用的结构化结果）。

要在 sinkhole 收 DNS/HTTP，需把引爆环境的 DNS 指向 sinkhole（`--isolate` 里可配 resolv）。若样本连非监听端口（看 §C 的 strace 连接），把端口加进 sinkhole `--extra-ports` 再跑，即可抓到该端口的完整请求包。

## 可行性验证结果（2026-09-19，测试机实测）
良性诱饵经完整 Linux/Wine 流水线，报告正确产出：

- **A 读凭证**：`newfstatat` 命中金丝雀 `…/Steam/ssfn0000000000000001` ✔
- **B 外发凭证**：sinkhole 命中金丝雀令牌 → `CANARY_EXFIL`（铁证）✔
- **C 外链地址**：`192.168.115.1:53`(strace) + `c2.mock-example.top:8080`(sinkhole) ✔
- **C2 请求包**：完整 POST 落盘 + 十六进制转储，可见回传的令牌 ✔

即：**在这台无虚拟化、~900MB 内存的 Linux 上，用 Wine 就能跑动态分析并抓到"外链地址 + 请求包 + 凭证外发"**。

## 已知限制（诚实说明）
- **Wine ≠ 完整 Windows**：依赖特定 Win32 API / 需要 VPet 进程环境（检测父进程、窗口）的载荷可能不完全触发。`report.md` 的"未观察到 ≠ 不存在"提示即为此。
- **harness 触发方式**：目前按 boot 导出序号 `#1` 无参调用来复现 .NET 桩的动作。多数 boot 从自身 overlay 读配置、不需入参；若某样本的 boot 需要桩传参才动，harness 可能触发不全——此时改用真 Windows 主机加载托管桩复核。
- TLS 只取 SNI（域名）；要 HTTPS 明文用 mitmproxy（见 `../dynamic/README.md`）。
- 结论应结合静态扫描（`vpetscan`）一起看：静态负责上架拦截，动态负责定性。
