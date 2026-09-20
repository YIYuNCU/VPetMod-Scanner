#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
动态分析 worker（自动化）：轮询审核服务的动态队列，认领任务→下载样本→在 Wine 沙箱引爆→回传外链地址/请求包。
审核员只在网页上传，动态分析由本 worker 自动完成，无需任何人登录服务器。

跑在一台装了 Wine 的隔离主机上（可与审核服务同机但**在容器外**，因为 scratch 容器跑不了 Wine）。
⚠️ 真引爆 = 在本机真跑 Windows 恶意代码。务必：可回滚快照 + 网络只放行 sinkhole + 跑完回滚。

用法：
  python3 dynamic-worker.py --server http://127.0.0.1:8740 --token <T> --sink 10.7.0.1 --isolate
  # 验证自动化管线（不引爆真样本，用良性诱饵代替引爆步骤）：
  python3 dynamic-worker.py --server http://127.0.0.1:8740 --token <T> --mock
  # 工作目录默认 /var/tmp/vpetdyn（Wine 前缀大，/tmp 常为 tmpfs 放不下）
"""
import argparse, json, os, subprocess, sys, time, urllib.request, zipfile, tarfile, tempfile, shutil

HERE = os.path.dirname(os.path.abspath(__file__))


def api(server, token, path, method="GET", data=None):
    r = urllib.request.Request(server.rstrip("/") + path, data=data, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data:
        r.add_header("Content-Type", "application/octet-stream")
    return urllib.request.urlopen(r, timeout=60)


def claim(a):
    try:
        resp = api(a.server, a.token, "/api/v1/dynamic/next")
    except Exception as e:
        print("[worker] 轮询失败:", e); return None
    if resp.status == 204:
        return None
    return json.loads(resp.read())


def download(a, tid, dst):
    resp = api(a.server, a.token, "/api/v1/tasks/%s/file" % tid)
    with open(dst, "wb") as f:
        shutil.copyfileobj(resp, f)


def extract(sample, outdir):
    """把样本解到 outdir；返回成功与否。仅 zip/tar 用标准库，7z/rar 尝试外部命令。"""
    try:
        if zipfile.is_zipfile(sample):
            with zipfile.ZipFile(sample) as z:
                z.extractall(outdir)
            return True
        if tarfile.is_tarfile(sample):
            with tarfile.open(sample) as t:
                t.extractall(outdir)
            return True
    except Exception as e:
        print("[worker] 解压失败:", e)
    for tool in (["7z", "x", "-y", "-o" + outdir, sample], ["unar", "-o", outdir, sample]):
        if shutil.which(tool[0]):
            if subprocess.run(tool, capture_output=True).returncode == 0:
                return True
    return False


def locate_boot(outdir, target):
    """target 是包内展示路径，如 name.zip!/mod/native/helper_5e.dll；取 !/ 之后映射到解压目录。"""
    inner = target.split("!/", 1)[1] if "!/" in target else target
    cand = os.path.join(outdir, inner)
    if os.path.isfile(cand):
        return cand
    base = os.path.basename(inner)
    for root, _, files in os.walk(outdir):
        if base in files:
            return os.path.join(root, base)
    return ""


def report_error(a, tid, msg):
    try:
        api(a.server, a.token, "/api/v1/tasks/%s/dynamic-error" % tid, "POST",
            json.dumps({"error": msg}).encode())
    except Exception as e:
        print("[worker] 回报错误失败:", e)


def process(a, job):
    tid = job["task_id"]
    print("[worker] 认领任务 %s (%s) target=%s" % (tid, job.get("filename"), job.get("target")))
    os.makedirs(a.work_dir, exist_ok=True)
    # 工作目录必须在大磁盘上：Wine 前缀一次 400M+，/tmp 常是几百 M 的 tmpfs 会被撑爆
    work = tempfile.mkdtemp(prefix="vpetdyn-", dir=a.work_dir)
    run = os.path.join(work, "run")
    try:
        det = ["bash", os.path.join(HERE, "detonate-linux.sh"),
               "--sink", a.sink, "--seconds", str(a.seconds), "--out", run]
        if a.pin_c2:
            # 钉住已知 C2 域名（hosts→127.0.0.1 + TLS MITM，沙箱内 sinkhole 应答；仍断网）：
            # 让外传分支真跑起来，POST 请求包被解密捕获。对不连这些域名的样本无副作用。
            det += ["--pin-c2", a.pin_c2]
        if a.isolate:
            det.append("--isolate")
        if a.serve:
            det += ["--serve", a.serve]

        if a.mock:
            det.append("--mock")  # 验证管线：良性诱饵，不执行真样本
        else:
            sample = os.path.join(work, job.get("filename") or "sample.bin")
            download(a, tid, sample)
            ext = os.path.join(work, "ext")
            os.makedirs(ext, exist_ok=True)
            boot = ""
            if extract(sample, ext):
                boot = locate_boot(ext, job.get("target") or "")
            if not boot:
                # 可能是单个 dll 上传，或找不到 boot；直接把样本本身当目标
                boot = sample
            det += ["--boot", boot]

        print("[worker] 引爆:", " ".join(det))
        env = dict(os.environ)
        if a.decoy_proc:
            # 诱饵进程喂 ReadProcessMemory 取 JWT 这条路。**2026-09-20 实测坐实：Wine+bwrap 下
            # 跨进程 ReadProcessMemory 必失败**（良性复现器 src/memprobe 100% 复现：OpenProcess/
            # VirtualQueryEx 成功、RPM 全返回 0）——载荷猎不到 JWT 就跳过外传。故此路在 Wine 下
            # 永远走不通，默认**关**（省一个 wine 实例，避开低内存机 dual-wine 堆损坏）。
            # 仅在真 Windows 沙箱（RPM 正常）上用 --decoy-proc 开启，届时可抓到凭证上传 POST。
            # 文件类金丝雀（loginusers/localconfig/steam.cfg 篡改）不依赖诱饵进程，照常捕获。
            env["SPAWN_DECOY_PROC"] = "1"
        d = subprocess.run(det, capture_output=True, text=True, timeout=a.seconds + 300, env=env)
        # detonate 走到第 5 步必写 files-after.txt；没有它说明引爆脚本早退（磁盘满/Wine 崩等），
        # 这属于基础设施故障，必须回报 error——绝不能让 analyze 贴一份"没观察到任何行为"的空报告冒充结论。
        if not os.path.isfile(os.path.join(run, "files-after.txt")):
            tail = ((d.stdout or "") + (d.stderr or "")).strip()[-300:]
            print("[worker] detonate 未完成:", tail.replace("\n", " | "))
            report_error(a, tid, "引爆脚本未跑完（无 files-after.txt）：" + tail[-200:])
            return

        ana = ["python3", os.path.join(HERE, "analyze-linux.py"), "--run", run,
               "--post", a.server, "--token", a.token, "--task", tid]
        if a.scanner:
            ana += ["--scanner", a.scanner]
        r = subprocess.run(ana, capture_output=True, text=True, timeout=180)
        tail = (r.stdout or "")[-300:]
        print("[worker] 分析回传:", tail.replace("\n", " | ")[-300:])
        if "已回传审核网页" not in (r.stdout or ""):
            report_error(a, tid, "分析或回传失败: " + (r.stderr or "")[-200:])
    except Exception as e:
        print("[worker] 处理异常:", e)
        report_error(a, tid, str(e))
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--token", default=os.environ.get("VPETSCAN_TOKEN", ""))
    ap.add_argument("--sink", default="127.0.0.1")
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--poll", type=int, default=8)
    ap.add_argument("--isolate", action="store_true")
    ap.add_argument("--serve", default="")
    ap.add_argument("--scanner", default="")
    ap.add_argument("--mock", action="store_true", help="用良性诱饵代替真引爆，验证自动化管线")
    ap.add_argument("--pin-c2", default="bvdpp.top,www.bvdpp.top,hhfyuxuz.top,www.hhfyuxuz.top",
                    help="钉住的 C2 域名，逗号分隔（hosts→127.0.0.1 + TLS MITM 抓外传 POST；空串关闭）。"
                         "默认含同族第二套 C2 hhfyuxuz.top——打下 bvdpp.top 不会让那个包失效")
    ap.add_argument("--decoy-proc", dest="decoy_proc", action="store_true", default=False,
                    help="拉起 steam.exe 诱饵进程喂 JWT 内存猎杀路径。默认关：Wine 下跨进程 "
                         "ReadProcessMemory 必失败（见 README 已知限制），此路走不通、还占一个 wine 实例。"
                         "仅在真 Windows 沙箱上开启以抓凭证上传 POST。")
    ap.add_argument("--once", action="store_true", help="只处理一个任务后退出（自检用）")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--work-dir", default="/var/tmp/vpetdyn",
                    help="工作目录（Wine 前缀 400M+/次，别放 tmpfs 的 /tmp）")
    a = ap.parse_args()
    print("[worker] 启动，轮询 %s 每 %ds%s" % (a.server, a.poll, "（mock 模式）" if a.mock else ""))
    while True:
        job = claim(a)
        if job:
            process(a, job)
            if a.once:
                return
        else:
            if a.once:
                print("[worker] 队列为空"); return
            time.sleep(a.poll)


if __name__ == "__main__":
    main()
