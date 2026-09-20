package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"vpetmod-scanner/internal/pe"
)

const highEntropy = 7.9

// analyzePE 对单个 PE 文件跑全部文件级规则。
func analyzePE(path string, data []byte) (FileInfo, []Finding) {
	sum := sha256.Sum256(data)
	fi := FileInfo{Path: path, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Kind: "pe-native"}
	var out []Finding
	add := func(rule, detail string, ev map[string]string) {
		out = append(out, newFinding(rule, path, detail, ev))
	}

	if name, ok := iocFileSHA256[fi.SHA256]; ok {
		add("IOC-FILE-SHA256", name, map[string]string{"sha256": fi.SHA256})
	}

	info, err := pe.Parse(data)
	if err != nil {
		return fi, out
	}
	if info.IsDotNet {
		fi.Kind = "pe-dotnet"
		out = append(out, analyzeDotNet(path, info)...)
		return fi, out
	}

	if name, ok := iocBodySHA256[info.BodySHA256]; ok {
		add("IOC-PE-BODY", name, map[string]string{"body_sha256": info.BodySHA256})
	}
	if t := info.Section(".text"); t != nil {
		if name, ok := iocTextSHA256[t.SHA256]; ok {
			add("IOC-PE-TEXT", name, map[string]string{"text_sha256": t.SHA256})
		}
	}
	if strings.EqualFold(info.ExportName, "boot_plain.dll") {
		add("PX-BOOT-EXPORT", "", map[string]string{"export_name": info.ExportName})
	}

	trailer := selfDescribingTrailer(info.Overlay)
	if ev, ok := bootTrailer(info.Overlay); ok {
		add("PX-BOOT-TRAILER", fmt.Sprintf("将手工映射 %s 与 %s", ev["mod1"], ev["mod2"]), ev)
		trailer = false // 已被更具体的规则解释
	}
	if ev, ok := payloadTrailer(info); ok {
		add("PX-PAYLOAD-TRAILER", fmt.Sprintf("自描述待解密区域 %s 与 %s", ev["region1"], ev["region2"]), ev)
	}
	if m := textInjectMarker(info, data); m != "" {
		add("PX-JS-INJECT", "", map[string]string{"marker": m})
	}

	var hot *pe.Section
	for k := range info.Sections {
		s := &info.Sections[k]
		if !s.Executable && s.RawSize >= 1024 && s.Entropy >= highEntropy && (hot == nil || s.Entropy > hot.Entropy) {
			hot = s
		}
	}
	if info.IsDLL && !info.ImportsReadable && hot != nil {
		ev := map[string]string{"section": hot.Name, "entropy": fmt.Sprintf("%.3f", hot.Entropy)}
		if trailer {
			ev["overlay_len"] = fmt.Sprint(len(info.Overlay))
			add("PX-PAYLOAD", "", ev)
		} else {
			add("GEN-PAYLOAD-NOIMPORT", "", ev)
		}
	} else if trailer {
		add("GEN-OVERLAY-TRAILER", "", map[string]string{"overlay_len": fmt.Sprint(len(info.Overlay))})
	}
	return fi, out
}

func analyzeDotNet(path string, info *pe.Info) []Finding {
	var out []Finding
	var hits []string
	for _, m := range pxStubMarkers {
		if info.HasMetaString(m) {
			hits = append(hits, m)
		}
	}
	for _, u := range info.UserStrings {
		if strings.HasPrefix(u, "px-orig-") {
			hits = append(hits, u)
		}
	}
	// 单个 GetProcAddressOrdinal 不够定性，至少两个家族标记才判。
	if len(hits) >= 2 {
		out = append(out, newFinding("PX-STUB", path, "", map[string]string{"markers": strings.Join(hits, ",")}))
	}

	// 外联地址/内嵌密钥对任何托管 DLL 都要提取（工具库、辅助文件、单独投递的载荷
	// 不一定继承 MainPlugin）——曾在合成样本上暴露：无 MainPlugin 提前返回导致漏检。
	out = append(out, networkFindings(path, info.UserStrings)...)

	if !info.HasMetaString("MainPlugin") {
		return out
	}
	hasAny := func(names ...string) bool {
		for _, n := range names {
			if info.HasMetaString(n) {
				return true
			}
		}
		return false
	}
	if hasAny("LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx", "LoadLibraryExW", "NativeLibrary") &&
		hasAny("GetProcAddress", "GetExport") &&
		hasAny("GetDelegateForFunctionPointer") {
		out = append(out, newFinding("GEN-STUB-NATIVE-EXEC", path, "", nil))
	}
	if hasAny("LoadFrom", "LoadFromAssemblyPath", "LoadFile", "Load") {
		for _, u := range info.UserStrings {
			if strings.HasSuffix(strings.ToLower(u), ".orig.dll") {
				out = append(out, newFinding("GEN-STUB-REFLECT-ORIG", path, "", map[string]string{"orig": u}))
				break
			}
		}
	}
	return out
}

var (
	urlRe    = regexp.MustCompile(`https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}`)
	ipRe     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d{1,5})?`)
	secretRe = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b`)
)

// networkFindings 从托管字符串里提取外联地址与内嵌密钥（托管插件的这些是明文）。
// PE 的 #US 堆用它（含裸 IP 提取）。
func networkFindings(path string, strs []string) []Finding {
	return networkFindingsX(path, strs, true)
}

// networkFindingsX：includeIP=false 时不提取裸 IP。文本/配置文件（deps.json 的版本号 13.0.0.0、
// schema 里的点分数字）会把版本号误判成 IP，所以文本提取只要 URL 与密钥，真实 C2 的 IP 一般也在 URL 里。
func networkFindingsX(path string, strs []string, includeIP bool) []Finding {
	var out []Finding
	urls := map[string]bool{}
	ips := map[string]bool{}
	secrets := map[string]bool{}
	for _, s := range strs {
		for _, u := range urlRe.FindAllString(s, -1) {
			urls[strings.TrimRight(u, "\".,)")] = true
		}
		for _, m := range secretRe.FindAllString(s, -1) {
			secrets[m] = true
		}
		// 不在含 URL 的串里再单独抓 IP，避免把 URL 里的主机重复计入
		if includeIP && !urlRe.MatchString(s) {
			for _, ip := range ipRe.FindAllString(s, -1) {
				if plausibleIP(ip) {
					ips[ip] = true
				}
			}
		}
	}
	for u := range urls {
		if note, ok := matchKnownC2(urlHost(u)); ok {
			out = append(out, newFinding("NET-KNOWN-C2", path, note, map[string]string{"url": u, "host": urlHost(u)}))
			continue
		}
		out = append(out, newFinding("NET-ENDPOINT", path, "", map[string]string{"url": u}))
	}
	for ip := range ips {
		out = append(out, newFinding("NET-ENDPOINT", path, "", map[string]string{"ip": ip}))
	}
	for s := range secrets {
		out = append(out, newFinding("NET-EMBEDDED-SECRET", path, "", map[string]string{"secret": maskSecret(s)}))
	}
	return out
}

// urlHost 从 URL 里取小写 host（剥 scheme/userinfo/port/path）。解析失败返回原串的小写。
func urlHost(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s, "]:") { // 保留 IPv6 字面量整体
		if !strings.Contains(s[i+1:], "]") {
			s = s[:i]
		}
	}
	return strings.ToLower(strings.Trim(s, "[]"))
}

// matchKnownC2：host 等于已知 C2 或其子域名时返回该 C2 的说明。
func matchKnownC2(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	for c2, note := range knownC2Hosts {
		if host == c2 || strings.HasSuffix(host, "."+c2) {
			return note, true
		}
	}
	return "", false
}

func plausibleIP(s string) bool {
	host := s
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	for _, p := range strings.Split(host, ".") {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	// 跳过版本号常见的 0.x / 1.x 噪声
	return !strings.HasPrefix(host, "0.") && !strings.HasPrefix(host, "1.0.")
}

func maskSecret(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…" + s[len(s)-4:] + fmt.Sprintf(" (len=%d)", len(s))
}

// payloadTrailer 识别 PxBridge 加密载荷的 108 字节自描述尾（boot 44 字节 trailer 的载荷侧对应物）：
// overlay 恰 0x6C 字节、末 u32 = 0x68，且 [0x58:0x68) 记录的两块待解密区域
// 与自身节表的 (VA, RawSize) 精确对齐。正常 PE 的 overlay 不会携带指向自身节的对齐表。
func payloadTrailer(info *pe.Info) (map[string]string, bool) {
	ov := info.Overlay
	if len(ov) != 0x6C || binary.LittleEndian.Uint32(ov[0x68:]) != 0x68 {
		return nil, false
	}
	match := func(rva, size uint32) string {
		for _, s := range info.Sections {
			if s.VirtAddr == rva && s.RawSize == size && s.Name != "" {
				return s.Name
			}
		}
		return ""
	}
	m1 := match(binary.LittleEndian.Uint32(ov[0x58:]), binary.LittleEndian.Uint32(ov[0x5C:]))
	m2 := match(binary.LittleEndian.Uint32(ov[0x60:]), binary.LittleEndian.Uint32(ov[0x64:]))
	if m1 == "" || m2 == "" {
		return nil, false
	}
	return map[string]string{"region1": m1, "region2": m2}, true
}

// 载荷 .text 是明文（只有 .rdata/.data 被加密），注入脚本片段以 movabs 立即数形式
// 直接留在代码节里。只认 __px 前缀家族标记，避免 saveGate 这类可能撞车的普通词。
var pxInjectMarkers = []string{"__pxGate", "self.__pxA", "__pxBridge"}

func textInjectMarker(info *pe.Info, data []byte) string {
	t := info.Section(".text")
	if t == nil || t.RawSize == 0 {
		return ""
	}
	lo, hi := int64(t.RawOffset), int64(t.RawOffset)+int64(t.RawSize)
	if lo < 0 || hi > int64(len(data)) {
		return ""
	}
	text := data[lo:hi]
	for _, m := range pxInjectMarkers {
		if strings.Contains(string(text), m) {
			return m
		}
	}
	return ""
}

// selfDescribingTrailer：overlay 最后 4 字节 = overlay 长度 - 4。
func selfDescribingTrailer(ov []byte) bool {
	if len(ov) < 12 {
		return false
	}
	return int(binary.LittleEndian.Uint32(ov[len(ov)-4:])) == len(ov)-4
}

// bootTrailer 识别 boot 配置尾：key[8] + mod1[16] + mod2[16] + u32(40)。
func bootTrailer(ov []byte) (map[string]string, bool) {
	if len(ov) != 44 || binary.LittleEndian.Uint32(ov[40:]) != 40 {
		return nil, false
	}
	m1, ok1 := dllName(ov[8:24])
	m2, ok2 := dllName(ov[24:40])
	if !ok1 || !ok2 {
		return nil, false
	}
	return map[string]string{"key": hex.EncodeToString(ov[:8]), "mod1": m1, "mod2": m2}, true
}

func dllName(b []byte) (string, bool) {
	s := string(bytes.TrimRight(b, "\x00"))
	if !strings.HasSuffix(strings.ToLower(s), ".dll") {
		return "", false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return "", false
		}
	}
	return s, true
}
