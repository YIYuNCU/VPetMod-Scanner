#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
隔离网沙箱用的 DNS + HTTP(S) + 裸TCP 汇聚点（sinkhole）。纯标准库。

作用：让被引爆的样本"以为"自己联网，从而暴露：
  - 外链地址：C2 域名(DNS/SNI)、每个连接的对端 IP:端口
  - 尝试发送的请求包：每个请求的完整原始字节都落盘到 requests/，可作为证据
  - 是否动态下发载荷：谁 GET 什么（--serve 回诱饵观察完整链路）
  - 是否窃取凭证：金丝雀令牌若出现在外发流量里即报 CANARY_EXFIL（铁证）

本机不放行任何流量到真实互联网：所有 DNS 解析到本机，所有连接由本脚本应答并记录。
TLS 默认只解析 ClientHello 的 SNI；给 --tls-cert/--tls-key 则升级为 MITM：用我们的证书真握手
终结 TLS，解密后的明文 HTTP 请求照常落盘 + 扫金丝雀（客户端须信任该证书——detonate-linux.sh
的 --pin-c2 会现生成证书并临时装入系统信任库，跑完移除）。

用法（隔离 VM 内，管理员）：
  python sinkhole.py --ip 10.0.0.1 --log sink.jsonl \
      --canary-file canaries.txt --serve decoy.bin \
      --extra-ports 1337,8443,4444,53413
把 VM 的 DNS 指到本机(127.0.0.1)；防火墙放行入站 UDP53 / 你监听的各 TCP 端口。
"""
import argparse, json, os, socket, ssl, struct, threading, time

LOG_LOCK = threading.Lock()
CANARIES = []   # [(token, label)]
ARGS = None
TLS_CTX = None  # 有 --tls-cert/--tls-key 时 443 走 MITM（终结 TLS 解密明文）
REQ_SEQ = 0
REQ_LOCK = threading.Lock()


def log(event, **kv):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event}
    rec.update(kv)
    line = json.dumps(rec, ensure_ascii=False)
    with LOG_LOCK:
        print(line, flush=True)
        if ARGS.log:
            with open(ARGS.log, "a", encoding="utf-8") as f:
                f.write(line + "\n")


def scan_canaries(blob, where, peer):
    for token, label in CANARIES:
        if token.encode() in blob:
            log("CANARY_EXFIL", severity="critical", token=token, canary=label,
                where=where, peer=peer,
                note="金丝雀令牌出现在外发流量中——确认样本窃取并回传了该凭证文件")


def save_raw(prefix, data, peer, port):
    """把一次请求的完整原始字节落盘，返回相对路径（作为证据）。"""
    global REQ_SEQ
    with REQ_LOCK:
        REQ_SEQ += 1
        n = REQ_SEQ
    os.makedirs(ARGS.dump_dir, exist_ok=True)
    fn = "%03d-%s-%s-%d.bin" % (n, prefix, str(peer).replace(":", "_"), port)
    path = os.path.join(ARGS.dump_dir, fn)
    with open(path, "wb") as f:
        f.write(data)
    return path


def hexdump(b, limit=256):
    b = b[:limit]
    out = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexs = " ".join("%02x" % c for c in chunk)
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("%04x  %-47s  %s" % (i, hexs, text))
    return "\n".join(out)


# ---------------- DNS ----------------
def dns_server(bind_ip, answer_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, 53))
    log("dns_listen", addr="%s:53" % bind_ip, answer=answer_ip)
    while True:
        try:
            data, peer = s.recvfrom(2048)
        except OSError:
            break
        try:
            name = parse_dns_qname(data)
            log("DNS", qname=name, peer=peer[0], note="样本解析的外链域名")
            s.sendto(build_dns_answer(data, answer_ip), peer)
        except Exception as e:
            log("dns_error", err=str(e))


def parse_dns_qname(data):
    i = 12
    labels = []
    while data[i] != 0:
        n = data[i]; i += 1
        labels.append(data[i:i+n].decode("latin1"))
        i += n
    return ".".join(labels)


def build_dns_answer(query, ip):
    tid = query[:2]
    hdr = tid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    i = 12
    while query[i] != 0:
        i += 1 + query[i]
    q = query[12:i+5]
    ans = b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack(">I", 60) + b"\x00\x04" + socket.inet_aton(ip)
    return hdr + q + ans


# ---------------- HTTP ----------------
def http_server(bind_ip, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port)); s.listen(64)
    log("http_listen", addr="%s:%d" % (bind_ip, port))
    while True:
        try:
            c, peer = s.accept()
        except OSError:
            break
        threading.Thread(target=http_conn, args=(c, peer, port), daemon=True).start()


def http_conn(c, peer, port):
    handle_http(c, peer, port, "http", "")


def handle_http(c, peer, port, proto, sni):
    """读一个完整 HTTP 请求：记录（原始字节落盘+hexdump+扫金丝雀）→ 应答（--serve 诱饵或空 200）。
    明文 80/8080 与 TLS MITM 解密后的 443 共用这一套。"""
    c.settimeout(15)
    try:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        if not data:
            return
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        req = lines[0].decode("latin1", "replace")
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            if k:
                headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
        clen = int(headers.get("content-length", "0") or "0")
        body = rest
        while len(body) < clen and len(body) < 20_000_000:
            chunk = c.recv(8192)
            if not chunk:
                break
            body += chunk

        raw = head + b"\r\n\r\n" + body
        saved = save_raw(proto, raw, peer[0], port)
        kv = dict(proto=proto, peer=peer[0], dport=port, request=req,
                  method=req.split(" ")[0] if " " in req else req,
                  host=headers.get("host", ""), ua=headers.get("user-agent", ""),
                  headers=headers, body_len=len(body), total_bytes=len(raw),
                  saved=saved, hex=hexdump(raw),
                  note="尝试发送的请求包（完整字节已落盘）" + ("；TLS 已解密" if proto != "http" else ""))
        if sni:
            kv["sni"] = sni
        log("REQUEST", **kv)
        scan_canaries(raw, proto + "-request", peer[0])

        payload = b""
        if ARGS.serve and os.path.isfile(ARGS.serve):
            with open(ARGS.serve, "rb") as f:
                payload = f.read()
            log("SERVED_PAYLOAD", peer=peer[0], request=req, bytes=len(payload),
                note="样本请求了文件——疑似动态下载第二阶段载荷；已返回诱饵")
        resp = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)) + payload
        c.sendall(resp)
    except Exception as e:
        log("http_error", peer=peer[0], err=str(e))
    finally:
        c.close()


# ---------------- TLS（SNI-only 或 MITM）----------------
def tls_server(bind_ip, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, port)); s.listen(64)
    if TLS_CTX:
        log("tls_listen", addr="%s:%d" % (bind_ip, port),
            note="TLS MITM：真握手终结 TLS，解密后的明文 HTTP 按普通请求落盘+扫金丝雀")
        while True:
            try:
                c, peer = s.accept()
            except OSError:
                break
            threading.Thread(target=tls_mitm_conn, args=(c, peer, port), daemon=True).start()
        return
    log("tls_listen", addr="%s:%d" % (bind_ip, port), note="仅解析 SNI；要明文给 --tls-cert/--tls-key 走 MITM")
    while True:
        try:
            c, peer = s.accept()
        except OSError:
            break
        threading.Thread(target=tls_conn, args=(c, peer, port), daemon=True).start()


def tls_mitm_conn(c, peer, port):
    """TLS MITM：先 MSG_PEEK 偷看 ClientHello 拿 SNI（不消费缓冲区，握手还能读到），
    再用我们的证书完成握手，之后按明文 HTTP 处理（请求体/表单原样可见）。
    握手失败（客户端不信任我们的证书等）→ 退回只记录 ClientHello，SNI 证据不丢。"""
    sni = ""
    try:
        c.settimeout(10)
        hello = c.recv(8192, socket.MSG_PEEK)
        sni = parse_sni(hello) or ""
    except Exception:
        pass
    try:
        tls = TLS_CTX.wrap_socket(c, server_side=True)
    except Exception as e:
        try:
            hello = c.recv(8192)  # 这次真消费，做落盘证据
        except Exception:
            hello = b""
        saved = save_raw("tls", hello, peer[0], port) if hello else ""
        log("REQUEST", proto="tls", peer=peer[0], dport=port,
            sni=sni or parse_sni(hello) or "", total_bytes=len(hello), saved=saved,
            note="TLS MITM 握手失败（%s）——证书未被信任或客户端要求不满足；退回仅记录 ClientHello" % str(e)[:100])
        if hello:
            scan_canaries(hello, "tls-clienthello", peer[0])
        c.close()
        return
    log("TLS_HANDSHAKE", peer=peer[0], dport=port, sni=sni,
        note="TLS MITM 握手成功——后续请求为解密后的明文")
    try:
        handle_http(tls, peer, port, "https-mitm", sni)
    except Exception as e:
        log("http_error", peer=peer[0], err=str(e))
    # handle_http 的 finally 负责 close


def tls_conn(c, peer, port):
    c.settimeout(10)
    try:
        hello = c.recv(8192)
        sni = parse_sni(hello)
        saved = save_raw("tls", hello, peer[0], port)
        log("REQUEST", proto="tls", peer=peer[0], dport=port, sni=sni or "",
            total_bytes=len(hello), saved=saved,
            note="TLS 连接；SNI=外链C2域名" if sni else "TLS 连接，无 SNI")
        scan_canaries(hello, "tls-clienthello", peer[0])
    except Exception as e:
        log("tls_error", peer=peer[0], err=str(e))
    finally:
        c.close()


def parse_sni(b):
    try:
        if len(b) < 5 or b[0] != 0x16:
            return None
        i = 5 + 4 + 2 + 32
        sid_len = b[i]; i += 1 + sid_len
        cs_len = struct.unpack(">H", b[i:i+2])[0]; i += 2 + cs_len
        comp_len = b[i]; i += 1 + comp_len
        i += 2  # ext total
        while i + 4 <= len(b):
            etype = struct.unpack(">H", b[i:i+2])[0]
            elen = struct.unpack(">H", b[i+2:i+4])[0]; i += 4
            if etype == 0:
                nlen = struct.unpack(">H", b[i+3:i+5])[0]
                return b[i+5:i+5+nlen].decode("latin1", "replace")
            i += elen
    except Exception:
        return None
    return None


# ---------------- 裸 TCP（任意端口，抓请求包）----------------
def raw_tcp_server(bind_ip, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((bind_ip, port)); s.listen(64)
    except OSError as e:
        log("raw_bind_error", port=port, err=str(e))
        return
    log("raw_listen", addr="%s:%d" % (bind_ip, port))
    while True:
        try:
            c, peer = s.accept()
        except OSError:
            break
        threading.Thread(target=raw_conn, args=(c, peer, port), daemon=True).start()


def raw_conn(c, peer, port):
    c.settimeout(8)
    try:
        data = b""
        while len(data) < 65536:
            try:
                chunk = c.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(chunk) < 8192:
                break
        saved = save_raw("tcp", data, peer[0], port) if data else ""
        log("REQUEST", proto="tcp", peer=peer[0], dport=port, total_bytes=len(data),
            saved=saved, hex=hexdump(data) if data else "",
            note="裸 TCP 请求包（完整字节已落盘）")
        if data:
            scan_canaries(data, "raw-tcp", peer[0])
    except Exception as e:
        log("raw_error", peer=peer[0], port=port, err=str(e))
    finally:
        c.close()


def main():
    global ARGS, CANARIES, TLS_CTX
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True, help="本 VM host-only 网卡地址（DNS 应答指向它）")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--log", default="sink.jsonl")
    ap.add_argument("--dump-dir", default="requests", help="每个请求原始字节的落盘目录")
    ap.add_argument("--canary-file", default="")
    ap.add_argument("--serve", default="", help="对任意 GET 返回的诱饵文件")
    ap.add_argument("--tls-cert", default="", help="给 443 配证书走 TLS MITM（解密明文请求）；缺省仅记录 SNI")
    ap.add_argument("--tls-key", default="")
    ap.add_argument("--extra-ports", default="", help="额外监听的裸 TCP 端口，逗号分隔（据 pktmon 观察到的对端端口补充）")
    ARGS = ap.parse_args()

    if ARGS.tls_cert and ARGS.tls_key:
        TLS_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        TLS_CTX.load_cert_chain(ARGS.tls_cert, ARGS.tls_key)
        log("tls_mitm_ready", cert=ARGS.tls_cert, note="443 将以该证书终结 TLS")

    if ARGS.canary_file and os.path.isfile(ARGS.canary_file):
        for ln in open(ARGS.canary_file, encoding="utf-8"):
            ln = ln.rstrip("\n")
            if not ln:
                continue
            tok, _, lab = ln.partition("\t")
            CANARIES.append((tok, lab or tok))
        log("canaries_loaded", count=len(CANARIES))

    threads = [
        threading.Thread(target=dns_server, args=(ARGS.bind, ARGS.ip), daemon=True),
        threading.Thread(target=http_server, args=(ARGS.bind, 80), daemon=True),
        threading.Thread(target=http_server, args=(ARGS.bind, 8080), daemon=True),
        threading.Thread(target=tls_server, args=(ARGS.bind, 443), daemon=True),
    ]
    for p in [x.strip() for x in ARGS.extra_ports.split(",") if x.strip()]:
        threads.append(threading.Thread(target=raw_tcp_server, args=(ARGS.bind, int(p)), daemon=True))
    for t in threads:
        t.start()
    log("sinkhole_up", ip=ARGS.ip, dump_dir=ARGS.dump_dir, note="Ctrl+C 结束")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("sinkhole_down")


if __name__ == "__main__":
    main()
