package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"vpetmod-scanner/internal/pe"
)

const highEntropy = 7.9

// utf16LEBytes 把 ASCII 串转成 UTF-16LE 字节序列，用于宽字符标记匹配。
func utf16LEBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// containsAnyEnc 在原始字节里找 s，ASCII 与 UTF-16LE 两种编码都试。
func containsAnyEnc(data []byte, s string) bool {
	if bytes.Contains(data, []byte(s)) {
		return true
	}
	return bytes.Contains(data, utf16LEBytes(s))
}

// pxArtifactHits 统计家族工件标记命中（跨整份文件，不限 .text）。
// 返回全部命中与其中的强标记命中，两者都按标记表顺序，保证结果稳定可复现。
func pxArtifactHits(data []byte) (hits, strong []string) {
	for _, m := range pxArtifactStrong {
		if containsAnyEnc(data, m) {
			hits = append(hits, m)
			strong = append(strong, m)
		}
	}
	for _, m := range pxArtifactWeak {
		if containsAnyEnc(data, m) {
			hits = append(hits, m)
		}
	}
	return hits, strong
}

// artifactMarkerFindings 按 §家族检测方法 3.4 的阈值出结论：
// >=3 命中且至少 1 个强标记 -> critical；否则只要有命中就给低危线索。
func artifactMarkerFindings(path string, data []byte) []Finding {
	hits, strong := pxArtifactHits(data)
	switch {
	case len(hits) >= artifactMinHits && len(strong) >= artifactMinStrong:
		return []Finding{newFinding("PX-ARTIFACT-MARKERS", path, "", map[string]string{
			"markers": strings.Join(hits, ","),
			"strong":  strings.Join(strong, ","),
		})}
	case len(hits) >= 1:
		return []Finding{newFinding("PX-ARTIFACT-MARKERS-WEAK", path, "", map[string]string{
			"markers": strings.Join(hits, ","),
		})}
	}
	return nil
}

// knownC2InBytes 在**原始字节**里找已知 C2 主机名，ASCII 与 UTF-16LE 都查。
//
// 为什么不能只靠 networkFindings：载荷在磁盘上只存裸 host（"bvdpp.top"），
// URL 是运行时用 "https://%s/gate.php" 这类模板拼出来的。urlRe 要求 scheme，
// 于是"明文出现已知 C2"这条承诺对真实载荷形态永远不成立；而原生 PE 更是一条
// 字符串都不提取。这里直接对字节做子串匹配，与文件形态无关。
func knownC2InBytes(path string, data []byte) []Finding {
	hosts := make([]string, 0, len(knownC2Hosts))
	for h := range knownC2Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts) // map 迭代顺序随机，排序保证报告与测试稳定
	var out []Finding
	for _, h := range hosts {
		if containsAnyEnc(data, h) {
			out = append(out, newFinding("NET-KNOWN-C2", path, knownC2Hosts[h], map[string]string{"host": h}))
		}
	}
	return out
}

// fptableFinding 已被删除：.fptable 是 Universal CRT 的函数指针缓存节
// （ucrt/internal/winapi_thunks.cpp 里的 #pragma bss_seg(".fptable")），
// 不是打包器产物，详见 rules.go 里的说明。

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

	// 以下三项只看原始字节，不依赖 PE 解析成功，原生与托管一视同仁。
	// 放在 pe.Parse 之前：解析失败的文件同样能做工件标记与 C2 取证。
	out = append(out, artifactMarkerFindings(path, data)...)
	out = append(out, knownC2InBytes(path, data)...)

	info, err := pe.Parse(data)
	if err != nil {
		return fi, out
	}
	if info.IsDotNet {
		fi.Kind = "pe-dotnet"
		out = append(out, analyzeDotNet(path, info)...)
		return fi, out
	}

	// 原生 PE 的明文外联地址同样是证据：此前 networkFindings 只喂托管 #US 与文本文件，
	// 原生 PE 一条字符串都不提取，导致 README 的"明文出现 C2 即判恶意"不成立。
	// 已知 C2 已由上面的 knownC2InBytes 兜住，这里补的是 NET-ENDPOINT / 内嵌密钥证据。
	//
	// 两个刻意的收窄（工坊 134 MOD 实测的降噪，见 §10）：
	//   - Authenticode 证书表整块跳过：签名 PE 里那张 CRL/证书链会贡献十几条
	//     crl.microsoft.com/pkiops/... "外联地址"，全是噪声（语料里 29 个文件各 12 条）。
	//   - includeIP=false：原生 PE 里的点分四段大多是版本号（4.0.0.0 出现了 19 次），
	//     与文本文件走同一套理由；真实 C2 以域名为准，且由 knownC2InBytes 兜底。
	strData := data
	if info.CertOffset > 0 && info.CertOffset < len(strData) {
		strData = strData[:info.CertOffset]
	}
	out = append(out, networkFindingsX(path, pe.Strings(strData, 6), false)...)

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

// externalDllString 找一个"非自身"的 *.dll 字符串常量（#US 堆）。
// 自身模块名先从**被扫文件名**里取（.NET 程序集清单里的模块名与文件名一致），
// 否则一个只有自身名字、却引用了原生加载三件套的辅助程序集会被误判。
func externalDllString(path string, info *pe.Info) string {
	self := strings.ToLower(pathBaseName(path))
	for _, u := range info.UserStrings {
		v := strings.TrimSpace(u)
		l := strings.ToLower(v)
		if !strings.HasSuffix(l, ".dll") || l == self {
			continue
		}
		if len(v) < 5 || len(v) > 128 || strings.ContainsAny(v, "\x00\r\n") {
			continue
		}
		return v
	}
	return ""
}

func pathBaseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
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

	hasAny := func(names ...string) bool {
		for _, n := range names {
			if info.HasMetaString(n) {
				return true
			}
		}
		return false
	}
	// 原生加载三件套齐备：这是"在宿主进程里取原生函数指针"的最小充分组合。
	nativeExecTrio := hasAny("LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryEx", "LoadLibraryExW", "NativeLibrary") &&
		hasAny("GetProcAddress", "GetExport") &&
		hasAny("GetDelegateForFunctionPointer")

	// 反射加载 *.orig.dll：判别力来自 ".orig.dll" 这个注入器自有命名，与是否插件入口无关，
	// 所以放在 MainPlugin 检查之前（辅助程序集同样可能干这事）。
	if hasAny("LoadFrom", "LoadFromAssemblyPath", "LoadFile", "Load") {
		for _, u := range info.UserStrings {
			if strings.HasSuffix(strings.ToLower(u), ".orig.dll") {
				out = append(out, newFinding("GEN-STUB-REFLECT-ORIG", path, "", map[string]string{"orig": u}))
				break
			}
		}
	}

	if !info.HasMetaString("MainPlugin") {
		// 非插件入口的辅助程序集：真正干活的 native DLL 由它按名加载，跨程序集边界。
		// 原先在这里直接 return，整条链一条发现都没有（实测 鸭科夫样本 CalcBridge.dll）。
		if nativeExecTrio {
			if t := externalDllString(path, info); t != "" {
				out = append(out, newFinding("GEN-HELPER-NATIVE-EXEC", path, "", map[string]string{"target": t}))
			}
		}
		return out
	}
	if nativeExecTrio {
		out = append(out, newFinding("GEN-STUB-NATIVE-EXEC", path, "", nil))
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
			urls[trimURLPunct(u)] = true
		}
		for _, m := range secretRe.FindAllString(s, -1) {
			secrets[m] = true
		}
		// 不在含 URL 的串里再单独抓 IP，避免把 URL 里的主机重复计入
		if includeIP && !urlRe.MatchString(s) {
			for _, loc := range ipRe.FindAllStringIndex(s, -1) {
				ip := s[loc[0]:loc[1]]
				if !plausibleIP(ip) {
					continue
				}
				// ASN.1 OID（2.5.4.15、1.3.6.1.4.1...）与长版本号会被 ipRe 截出前四段，
				// 看它是不是更长点分数字串的一截；是就跳过（工坊语料里 1.3.6.1 ×10、2.5.4.15 ×9）。
				if loc[0] > 0 && (s[loc[0]-1] == '.' || isDigit(s[loc[0]-1])) {
					continue
				}
				if loc[1] < len(s) && (s[loc[1]] == '.' || isDigit(s[loc[1]])) {
					continue
				}
				ips[ip] = true
			}
		}
	}
	for u := range urls {
		host := urlHost(u)
		if note, ok := matchKnownC2(host); ok {
			out = append(out, newFinding("NET-KNOWN-C2", path, note, map[string]string{"url": u, "host": host}))
			continue
		}
		// 载荷把 URL 存成 printf 模板（"https://%s/gate.php"，host 运行时填入）。
		// host 位是 "%s" 时它不是一个外联地址，塞进审核页只会污染「外联地址」板块；
		// 真正有判别力的域名由 knownC2InBytes 从裸 host 字节里取。
		if strings.Contains(host, "%") {
			continue
		}
		// 命名空间/标识符类 URL（XML namespace、文档 ID、模板占位符）不是外联目标，
		// 却大量出现在完全正常的 DLL 与配置文件里。已知 C2 的判定在上面，不受此影响。
		if uriOnlyHost(host) {
			continue
		}
		// 相邻字符串被拼在一起时会切出 "http://https://aka.ms/..." 这种伪 URL，
		// host 位退化成 scheme 名。真实内网短名（http://myserver/api）不在此列，照常保留。
		if host == "http" || host == "https" || host == "ftp" || host == "www" {
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

// trimURLPunct 去掉从二进制里抠 URL 时常见的尾部标点/括号残留
// （例如 "see https://gcc.gnu.org/bugs/):" 会整段匹配）。合法 URL 不会以 : ; , 结尾，
// 所以这些字符可以直接裁掉；端口号以数字结尾，不受影响。
func trimURLPunct(u string) string {
	return strings.TrimRight(u, "\".,);:'`]>}")
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// uriOnlyHosts 只作标识符用、不会是外联目标的 host。
//
// 依据：工坊 134 个 MOD 语料里 NET-ENDPOINT 的命中排行前 30 里，绝大多数是这一类——
// XML 命名空间（w3.org、purl.org、ns.adobe.com、james.newtonking.com）、
// 文档/规范标识（color.org、aiim.org、iec.ch）、以及 OpenXML/XMLSchema 的 schema 主机。
// 它们对审核员是纯噪声，会淹掉真正有价值的端点（实测：一个正常 MOD 报了 10 条，
// 其中 8 条是命名空间，只有 vpetllm.ycxom.com / api.openai.com 等 3 条有信息量）。
//
// 注意这是**精确 host 匹配**，且排在 matchKnownC2 之后——即便某个 C2 域被误列进来，
// NET-KNOWN-C2 也已经先命中了。
var uriOnlyHosts = map[string]bool{
	"www.w3.org": true, "w3.org": true,
	"purl.org": true, "xmlns.com": true, "www.xmlns.com": true,
	"ns.adobe.com": true, "www.aiim.org": true, "www.color.org": true, "www.iec.ch": true,
	"james.newtonking.com": true,
	"schemas.microsoft.com": true, "schemas.xmlsoap.org": true,
	"openxmlformats.org": true, "schemas.openxmlformats.org": true,
	"purl.oclc.org": true,
}

// placeholderHosts 文档/模板里的占位域名，出现即说明是示例而不是真实端点。
var placeholderHosts = map[string]bool{
	"example.com": true, "www.example.com": true, "example.org": true, "example.net": true,
	"your-domain": true, "yourdomain.com": true, "your-domain.com": true,
	"domain.com": true, "changeme.com": true, "test.com": true,
}

func uriOnlyHost(host string) bool {
	if uriOnlyHosts[host] || placeholderHosts[host] {
		return true
	}
	// example.com 的子域同样是 RFC 2606 保留的示例域
	return strings.HasSuffix(host, ".example.com") || strings.HasSuffix(host, ".example.org") ||
		strings.HasSuffix(host, ".example.net")
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
	if strings.HasPrefix(host, "0.") || strings.HasPrefix(host, "1.0.") {
		return false
	}
	// 后两段为 0 的是网络地址（x.y.0.0），不会被当作主机连出去。
	// 实测误报来源：程序集版本串 "4.0.0.0" 在工坊语料里出现 19 次。
	parts := strings.Split(host, ".")
	if len(parts) == 4 && parts[2] == "0" && parts[3] == "0" {
		return false
	}
	return true
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
