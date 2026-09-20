#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
汇总 Linux(Wine) 引爆的采集结果，按必查项出 report.md。纯标准库。
输入：strace.log*（文件/网络/进程系统调用）、sink.jsonl + requests/（外链与请求包）、
     capture.pcap（金丝雀令牌搜索）、files-before/after.txt（落地 PE diff）、canaries.txt。
回答：A 读凭证 / B 外发凭证(金丝雀) / C 外链地址 / C2 请求包 / D 动态载荷 / E 持久化(注册表) / F 子进程。
"""
import argparse, glob, json, os, re, subprocess, sys, urllib.request

# Windows 控制台 GBK 编不了 ⚠ 等字符时别让 print 崩掉（报告文件本身始终是 UTF-8）。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

def load_canaries(path):
    toks = []
    if path and os.path.isfile(path):
        for ln in open(path, encoding="utf-8"):
            ln = ln.rstrip("\n")
            if not ln:
                continue
            tok, _, lab = ln.partition("\t")
            toks.append((tok, lab or tok))
    return toks

STEAM_RE = re.compile(r'ssfn|loginusers\.vdf|config\.vdf|SteamAppData|/Steam/|wallet\.dat|Login Data|logins\.json|密码', re.I)
FILEOP_RE = re.compile(r'([a-z0-9_]+)\((?:AT_FDCWD,\s*)?"([^"]+)"[^)]*\)\s*=\s*(-?\d+)')
CONNECT_RE = re.compile(r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*(?:sin6?_port=htons\((\d+)\))?[^}]*?(?:sin_addr=inet_addr\("([^"]+)"\)|inet_pton\([^,]+,\s*"([^"]+)")')
EXECVE_RE = re.compile(r'execve\("([^"]+)"')
# sendto/send 的内容与目标：断网(--unshare-net)下 pcap/sinkhole 都拿不到包，strace 记录的
# 发送内容是金丝雀铁证与 C2 域名的唯一来源（DNS 查询里域名以 label 序列明文出现）。
SENDTO_RE = re.compile(r'send(?:to)?\(\d+, "((?:[^"\\]|\\.)*)", \d+(?:, [^,]+)?(?:, \{sa_family=AF_INET6?,[^}]*(?:inet_addr\("([^"]+)"\)|inet_pton\([^,]+,\s*"([^"]+)")[^}]*\})?')

# 已证实的 PxBridge C2：3803426816(天籁之音) 两个载荷静态解密后从 .rdata 提取
# （另一位开发者完成解密；原始样本中这些在加密节内，静态明文扫描不可见）。
KNOWN_C2 = {
    "bvdpp.top": "已知 PxBridge C2：JWT/凭据外传(/ey/2.php /vdf/2.php) + SteamUI 注入接口(/gate.php /steamhelper*)",
    "hhfyuxuz.top": "同族第二套 PxBridge C2（跨游戏投放包 鸭科夫假红信mod/SteamCFyinxiao.dll）："
                    "/gate.php 远程开关 + /steamhelper* 页面引导；打下 bvdpp.top 不会让这个包失效",
}
# 同一样本解密字符串里的关联域名清单：无证据表明当前样本逐一通信，仅用于命中提示，不定性。
WATCH_DOMAINS = [
    "skylinemediaworld.top", "ultracloudmarket.top", "fwqoop.org", "fufjxzl.org",
    "fuuewq.org", "nexustechsolution.top", "advancedwebfactory.top", "fastdigitalcenter.top",
    "vorqube.com", "luminovastella.top", "veloriquantica.top", "quantumservernode.top",
    "zentravolix.top", "toralumivent.top", "clyveron.org", "vexorandria.top",
    "yywuxfll.top", "ufyyekkl.top", "uuyyywuul.top", "zentryxful.icu", "llxzpfsj.top",
]

def domain_note(s):
    """对外联目标字符串（域名/SNI/host/URL）标注已知 C2 或关联域名。"""
    t = s.lower()
    for d, note in KNOWN_C2.items():
        if d in t:
            return d, note, True
    for d in WATCH_DOMAINS:
        if d in t:
            return d, "PxBridge 样本解密字符串中的关联域名（未证实通信，扩大检索用）", False
    return "", "", False

# strace 转义串里的域名匹配：DNS 报文里 '.' 变成 1 字节长度前缀（转义后 1~4 字符），
# 所以 bvdpp.top 可能以 "bvdpp\3top" 形态出现——把 '.' 展开为"1~6 个任意字符"再搜。
_esc_domain_cache = {}
def domain_in_escaped(text):
    t = text.lower()
    for d in list(KNOWN_C2) + WATCH_DOMAINS:
        rx = _esc_domain_cache.get(d)
        if rx is None:
            rx = re.compile(re.escape(d).replace(r"\.", r"[\s\S]{1,6}"))
            _esc_domain_cache[d] = rx
        if rx.search(t):
            return d
    return ""

def read_strace(run):
    files, conns, execs, sends = [], [], [], []
    for fp in sorted(glob.glob(os.path.join(run, "strace.log*"))):
        try:
            data = open(fp, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for m in FILEOP_RE.finditer(data):
            sc, path, ret = m.group(1), m.group(2), m.group(3)
            if sc in ("connect","bind","sendto","execve"):
                continue
            files.append((sc, path, ret))
        for m in CONNECT_RE.finditer(data):
            port = m.group(1) or ""
            ip = m.group(2) or m.group(3) or ""
            if ip:
                conns.append((ip, port))
        for m in EXECVE_RE.finditer(data):
            execs.append(m.group(1))
        for m in SENDTO_RE.finditer(data):
            content = m.group(1)
            dst = m.group(2) or m.group(3) or ""
            if content:
                sends.append((dst, content))
    return files, conns, execs, sends

def read_sink(path):
    dns, reqs, exfil, served, tls_ok = [], [], [], [], []
    if path and os.path.isfile(path):
        for ln in open(path, encoding="utf-8"):
            try:
                o = json.loads(ln)
            except Exception:
                continue
            e = o.get("event")
            if e == "DNS": dns.append(o.get("qname", ""))
            elif e == "REQUEST": reqs.append(o)
            elif e == "CANARY_EXFIL": exfil.append(o)
            elif e == "SERVED_PAYLOAD": served.append(o)
            elif e == "TLS_HANDSHAKE": tls_ok.append(o)
    return dns, reqs, exfil, served, tls_ok

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--canaries", default="")
    ap.add_argument("--scanner", default="")
    ap.add_argument("--post", default="", help="审核服务地址，如 http://host:8740，回传动态结果到网页")
    ap.add_argument("--token", default="", help="审核服务 Bearer 令牌")
    ap.add_argument("--task", default="", help="回传到的任务 ID（与 --sha256 二选一）")
    ap.add_argument("--sha256", default="", help="按 SHA256 匹配任务回传")
    args = ap.parse_args()
    run = args.run
    canaries = load_canaries(args.canaries or os.path.join(run, "canaries.txt"))
    tokens = [t for t, _ in canaries]
    files, conns, execs, sends = read_strace(run)
    dns, reqs, exfil, served, tls_ok = read_sink(os.path.join(run, "sink.jsonl"))
    out = []
    def w(s=""): out.append(s)

    w("# VPet MOD 动态分析报告 (Linux/Wine)")
    w("")
    w(f"运行目录：`{run}`  strace文件事件：{len(files)}  连接：{len(conns)}  金丝雀：{len(canaries)}")
    w("")

    # A 读凭证
    w("## A. 是否读取 Steam / 凭证文件")
    cred = [(sc, p, r) for sc, p, r in files if STEAM_RE.search(p) or any(t in p for t in tokens)]
    if cred:
        w("**命中**：进程访问了凭证相关文件：")
        w("")
        w("| 系统调用 | 路径 | 返回 |")
        w("|---|---|---|")
        seen = set()
        for sc, p, r in cred:
            if (sc, p) in seen: continue
            seen.add((sc, p))
            w(f"| {sc} | {p} | {r} |")
    else:
        w("_未在 strace 中看到凭证文件读取。_")
    w("")

    # B 外发凭证（金丝雀）。取证要点：无论正负都必须留痕——种了哪些诱饵、有没有外发、
    # 外发的原始包长什么样。负结果也要显式记录（"种了 N 个、窗口内未见外发"），不能静默省略。
    w("## B. 是否上传/外发凭证（金丝雀铁证）")
    canary_labels = [lab.split(" :: ")[0] for _, lab in canaries]  # 只留标签，去掉 " :: 路径" 噪声
    if canaries:
        w(f"已种植 **{len(canaries)}** 个金丝雀诱饵并全程监控外发通道（strace sendto / sinkhole / pcap）：")
        w("")
        for _, lab in canaries:
            w(f"- {lab}")
        w("")
    else:
        w("_未找到 canaries.txt——本次没有种植金丝雀（引爆脚本可能早退）。_")
        w("")
    hits = []
    exfil_packets = []  # 命中金丝雀的外发原始包，留作数据取证证据
    for o in exfil:
        hits.append(f"sinkhole: token={o.get('token')} canary={o.get('canary')} peer={o.get('peer')} where={o.get('where')}")
    # 断网模式下 pcap/sinkhole 都拿不到包——strace 记录的 sendto() 内容是唯一证据源：
    # 外发字节（DNS/HTTP/任意协议）里出现金丝雀令牌，就证明数据真的离开了进程。
    for dst, content in sends:
        for t, lab in canaries:
            if t in content:
                hits.append(f"strace sendto 内容出现金丝雀令牌 {t}（{lab}）→ 目标 {dst or '未知'}——数据已交给网络栈")
                # 保留这一包的原始内容（截断到 512B）作为取证证据，同时并入 §C2 请求包
                snippet = content[:512]
                exfil_packets.append({"proto": "sendto", "peer": dst or "?", "dport": 0,
                                      "request": f"金丝雀 {lab} 外发", "bytes": len(content), "hex": snippet,
                                      "canary": t})
    pcap = os.path.join(run, "capture.pcap")
    if os.path.isfile(pcap) and tokens:
        blob = open(pcap, "rb").read()
        txt = blob.decode("latin1", "replace")
        for t, lab in canaries:
            if t in txt:
                hits.append(f"pcap: 抓包中出现金丝雀令牌 {t}（{lab}）——数据确实离开了进程")
    reqs = exfil_packets + reqs  # 外发证据包排在最前
    if hits:
        w("**确认外发凭证（严重）**：")
        for h in hits: w(f"- {h}")
        if exfil_packets:
            w("")
            w("外发原始包（取证证据，完整字节见 §C2）：")
            for p in exfil_packets:
                w(f"- → {p['peer']}（{p['bytes']}B）：`{str(p['hex'])[:200]}`")
    elif canaries:
        w("_窗口内所有监控通道均未见任何金丝雀令牌外发——本次未观察到凭证外传（Wine 离线窗口；"
          "未观察到≠不存在，可能是延时/条件触发或加密后外发）。_")
    w("")

    # C 外链地址
    w("## C. 外链地址汇总（IP / 域名 / 端口）")
    rows = []
    for ip, port in conns:
        if ip in ("127.0.0.1", "::1") and not port:
            pass
        rows.append((f"{ip}:{port}" if port else ip, "connect", "strace"))
    # sendto 内容里提取的域名（DNS 查询明文）：断网下这是 C2 域名的直接证据
    seen_snd = set()
    for dst, content in sends:
        d = domain_in_escaped(content)
        if d and (d, dst) not in seen_snd:
            seen_snd.add((d, dst))
            rows.append((f"{d} (发送内容明文)" + (f" → {dst}" if dst else ""), "sendto", "strace"))
    for q in dns:
        rows.append((q, "DNS", "sinkhole"))
    for o in reqs:
        if o.get("proto") == "tls" and o.get("sni"):
            rows.append((f"{o['sni']}:{o.get('dport')} (TLS)", "tls", "sinkhole"))
        elif o.get("proto") == "https-mitm":
            tgt = o.get("host") or o.get("sni") or o.get("peer")
            rows.append((f"{tgt}:{o.get('dport')} (HTTPS·已解密)", "https-mitm", "sinkhole"))
        elif o.get("proto") == "http":
            rows.append((f"{o.get('host')}:{o.get('dport')} (HTTP)", "http", "sinkhole"))
        else:
            rows.append((f"{o.get('peer')}:{o.get('dport')} ({o.get('proto')})", o.get("proto"), "sinkhole"))
    if tls_ok:
        rows.append((f"TLS MITM 握手成功 ×{len(tls_ok)}（明文已解密落盘）", "tls-mitm", "sinkhole"))
    rows = sorted(set(rows))
    c2_hits = []  # (域名, 说明) —— 已知 C2 命中（铁证级，直接判恶意）
    if rows:
        w("| 目标(IP/域名:端口) | 协议 | 来源 | 标注 |")
        w("|---|---|---|---|")
        for t, pr, src in rows:
            d, note, is_c2 = domain_note(t)
            mark = f"⚠ **{note}**" if is_c2 else (note if d else "")
            if is_c2 and (d, note) not in c2_hits:
                c2_hits.append((d, note))
            w(f"| {t} | {pr} | {src} | {mark} |")
        with open(os.path.join(run, "endpoints.csv"), "w", encoding="utf-8") as f:
            f.write("target,proto,source,note\n")
            for t, pr, src in rows:
                d, note, _ = domain_note(t)
                f.write(f'"{t}","{pr}","{src}","{note}"\n')
    else:
        w("_未观察到外联尝试。_")
    w("")

    # C2 请求包
    w("## C2. 尝试发送的请求包（完整内容）")
    # 发往已知 C2 的 POST = 凭证上传被捕获（钉住域名 + TLS MITM 解密后可见）。
    # 注意：PxBridge 的 d= 表单本身还有样本自加密层（AES+Base64），解密 TLS 后看到的仍是密文 blob——
    # 但"读了金丝雀凭证 → POST 到 C2 外传端点"的链条已足够定性；金丝雀令牌若在明文层则 §B 直接铁证。
    c2_posts = []
    for o in reqs:
        tgt = " ".join(str(o.get(k) or "") for k in ("host", "sni", "request", "peer"))
        if str(o.get("method", "")) == "POST" and domain_note(tgt)[2]:
            c2_posts.append(o)
    if c2_posts:
        w(f"**⚠ 其中 {len(c2_posts)} 个 POST 发往已知 C2 外传端点——凭证上传已被捕获**（请求体见下方）。")
        w("")
    if reqs:
        w(f"共捕获 {len(reqs)} 个外发请求（原始字节在 requests/）：")
        for i, r in enumerate(reqs[:30], 1):
            w("")
            w(f"### 请求 #{i} — {r.get('proto')} 到 {r.get('peer')}:{r.get('dport')} ({r.get('total_bytes')} 字节)")
            if r.get("host"): w(f"- Host: {r['host']}")
            if r.get("sni"): w(f"- TLS SNI: {r['sni']}")
            if r.get("request"): w(f"- 请求行: `{r['request']}`")
            if r.get("saved"): w(f"- 原始字节文件: `{r['saved']}`")
            if r.get("hex"):
                w("```")
                for line in str(r["hex"]).split("\n")[:24]: w(line)
                w("```")
    else:
        w("_未捕获外发请求包。_ 若 §C 显示连了非监听端口，把该端口加进 sinkhole --extra-ports 再跑。")
    w("")

    # D 动态载荷
    w("## D. 是否动态下发/下载攻击载荷")
    dl = [f"GET {o.get('host')} :: {o.get('request')}" for o in reqs
          if o.get("proto") in ("http", "https-mitm") and str(o.get("request", "")).startswith("GET")]
    dl += [f"下载：{o.get('request')}（回诱饵 {o.get('bytes')} 字节）" for o in served]
    dropped = diff_files(run)
    newpe = [p for p in dropped if is_pe(p)]
    if dl:
        for d in dl[:30]: w(f"- {d}")
        w("")
    if newpe:
        w("**运行期间新落地的 PE（疑似第二阶段载荷）**：")
        for p in newpe:
            line = f"- `{p}`"
            if args.scanner and os.path.isfile(args.scanner):
                try:
                    r = subprocess.run([args.scanner, "scan", p], capture_output=True, text=True, timeout=60)
                    first = next((l for l in r.stdout.splitlines() if l.startswith("[")), "")
                    if first: line += f"\n  - vpetscan: {first.strip()}"
                except Exception:
                    pass
            w(line)
    elif not dl:
        w("_未观察到动态下载或新 PE 落地。_ 隔离网下二阶段可能没被拉取——用 sinkhole --serve 提供诱饵再跑。")
    w("")

    # D2 SteamUI 客户端篡改落地（3803426816 assetplu8：改写 steamui 资源 + 写 steam.cfg 抑制自更新，
    # 备份到 _local_patch_backup/manifest.sha256）。这些是非 PE 落地物，不进 §D 的 PE 清单，单列。
    w("## D2. 是否篡改 Steam 客户端（SteamUI 改写落地）")
    tamper_sig = ("_local_patch_backup", "steam.cfg", "/sp.js", "manifest.sha256", "/steamui/")
    tamper = [p for p in dropped if any(s in p for s in tamper_sig)]
    if tamper:
        w("**命中**：运行期间落地了 SteamUI 篡改 / 抑制自更新的痕迹文件：")
        w("")
        for p in tamper[:40]:
            note = ""
            if p.endswith("steam.cfg"):
                note = "  ← 抑制 Steam 自更新（阻止客户端更新覆盖被改写的资源）"
            elif "_local_patch_backup" in p:
                note = "  ← 改写前备份/清单，供还原与校验"
            w(f"- `{p}`{note}")
        w("")
        w("> 对照另一位开发者的静态解密报告 §7.1/§10.2：assetplu8 定位 steamui 资源→备份→改写→写 steam.cfg。"
          "本次动态运行坐实了备份与 steam.cfg 落地环节（改写具体资源受 Wine 下 steamui 内容差异影响可能跳过）。")
    else:
        w("_未观察到 SteamUI 改写 / steam.cfg 落地。_")
    w("")

    # E 持久化（Wine 注册表 + 启动目录）
    w("## E. 是否建立持久化")
    persist = []
    for reg in ("system.reg", "user.reg"):
        rp = os.path.join(run, "prefix", reg)
        if os.path.isfile(rp):
            data = open(rp, encoding="utf-8", errors="replace").read()
            for key in ("CurrentVersion\\\\Run", "Winlogon", "Userinit"):
                if key.replace("\\\\", "\\") in data:
                    # 只在 diff 出新增时才有意义，这里粗判存在 Run 段的可疑写入
                    pass
    startup = [p for p in dropped if "Start Menu" in p and "Startup" in p]
    runkeys = [p for p in dropped if p.endswith("user.reg") or p.endswith("system.reg")]
    if startup: persist.append("启动文件夹新增：" + ", ".join(startup))
    if runkeys: persist.append("注册表文件被修改（对比 prefix/*.reg 的 Run 段确认）：" + ", ".join(runkeys))
    if persist:
        for p in persist: w(f"- {p}")
    else:
        w("_未发现启动项/注册表 Run 方面的持久化（如需精确，diff prefix/user.reg 的 Run 段）。_")
    w("")

    # F 子进程
    w("## F. 进程创建 (execve)")
    interesting = [e for e in sorted(set(execs)) if not e.startswith("/usr/") and not e.startswith("/bin/") and "wine" not in e.lower()]
    show = interesting or sorted(set(execs))
    if show:
        for e in show[:40]: w(f"- {e}")
    else:
        w("_无。_")
    w("")

    # 结论
    w("## 结论摘要")
    w(f"- A 读取凭证：{'是' if cred else '未观察到'}")
    w(f"- B 外发凭证（金丝雀命中）：{'**是（铁证）**' if hits else '未命中'}")
    w(f"- C 外链地址：{len(rows)} 个" + (f"，其中 **已知 C2 命中 {len(c2_hits)} 个：{', '.join(d for d, _ in c2_hits)}**" if c2_hits else ""))
    if c2_posts:
        w(f"- **C2 凭证外传 POST 已捕获 {len(c2_posts)} 个（域名钉住 + TLS MITM 解密）**——上传行为坐实")
    w(f"- D 动态下发载荷：{'是/疑似' if (dl or newpe) else '未观察到'}")
    w(f"- D2 篡改 Steam 客户端：{'**是（落地痕迹）**' if tamper else '未观察到'}")
    w(f"- E 持久化：{'是' if persist else '未观察到'}")
    w("")
    w("> Wine 不是完整 Windows；部分依赖特定 API/进程环境的样本可能不完全触发。未观察到≠不存在，建议多跑、延长时长、开 --serve 诱导二阶段，必要时上真 Windows 主机复核。")

    rp = os.path.join(run, "report.md")
    open(rp, "w", encoding="utf-8").write("\n".join(out))
    print("[OK] 报告：" + rp)

    # 结构化 dynamic.json（可回传审核网页）。命中已知 C2 / 金丝雀外发 / SteamUI 篡改落地：直接判恶意。
    verdict = "malicious" if (hits or c2_hits or tamper) else ("suspicious" if (rows or cred) else "clean")
    dyn = {
        "source": "linux-wine",
        "verdict": verdict,
        "endpoints": [{"target": t, "proto": pr, "source": src,
                       **({"result": domain_note(t)[1]} if domain_note(t)[0] else {})}
                      for t, pr, src in rows],
        "requests": [{"proto": r.get("proto"), "peer": r.get("peer"), "dport": r.get("dport"),
                      "host": r.get("host"), "sni": r.get("sni"), "request": r.get("request"),
                      "bytes": r.get("bytes") or r.get("total_bytes"), "hex": r.get("hex")} for r in reqs[:50]],
        "credential_access": list(dict.fromkeys(f"{sc} {p}" for sc, p, _ in cred))[:50],
        "canaries_planted": canary_labels,   # 种了哪些诱饵（取证：负结果也要能看出监控过什么）
        "canary_count": len(canaries),
        "exfil_checked": bool(canaries),     # 是否真的做了外发监控（区分"没查"与"查了没发现"）
        "canary_exfil": hits,
        "dropped_pe": newpe,
        "steamui_tamper": tamper[:40],
        "note": "Wine 动态分析；未观察到≠不存在"
                + (f"；命中已知 C2：{', '.join(d for d, _ in c2_hits)}" if c2_hits else "")
                + (f"；捕获 {len(c2_posts)} 个发往已知 C2 的 POST（TLS MITM 解密）——凭证外传坐实" if c2_posts else "")
                + ("；SteamUI 篡改落地（steam.cfg/_local_patch_backup）" if tamper else ""),
    }
    dj = os.path.join(run, "dynamic.json")
    open(dj, "w", encoding="utf-8").write(json.dumps(dyn, ensure_ascii=False, indent=2))
    print("[OK] 结构化结果：" + dj)

    if args.post:
        if args.task:
            url = args.post.rstrip("/") + "/api/v1/tasks/" + args.task + "/dynamic"
        elif args.sha256:
            url = args.post.rstrip("/") + "/api/v1/dynamic?sha256=" + args.sha256
        else:
            print("[!] --post 需要 --task 或 --sha256"); print("\n".join(out[:30])); return
        req = urllib.request.Request(url, data=json.dumps(dyn).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        if args.token:
            req.add_header("Authorization", "Bearer " + args.token)
        try:
            with urllib.request.urlopen(req, timeout=30) as f:
                print("[OK] 已回传审核网页：" + url + "  (" + str(f.status) + ")")
        except Exception as e:
            print("[!] 回传失败：" + str(e))
    print("\n".join(out[:30]))

def diff_files(run):
    b, a = os.path.join(run, "files-before.txt"), os.path.join(run, "files-after.txt")
    if not (os.path.isfile(b) and os.path.isfile(a)):
        return []
    before = {}
    for ln in open(b, encoding="utf-8", errors="replace"):
        p, _, s = ln.rstrip("\n").rpartition("\t")
        if p: before[p] = s
    dropped = []
    for ln in open(a, encoding="utf-8", errors="replace"):
        p, _, s = ln.rstrip("\n").rpartition("\t")
        if p and (p not in before or before[p] != s):
            dropped.append(p)
    return dropped

def is_pe(p):
    try:
        with open(p, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False

if __name__ == "__main__":
    main()
