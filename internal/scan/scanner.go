package scan

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"vpetmod-scanner/internal/archive"
)

// Limits 防压缩炸弹与超大目录；任何一项超限都只跳过并记 warning，不中断整次扫描。
type Limits struct {
	MaxFileBytes    int64 // 单文件（解压后）读入上限
	MaxTotalBytes   int64 // 本次扫描累计读入上限
	MaxEntries      int   // 本次扫描累计文件数上限
	MaxArchiveDepth int   // 压缩包嵌套层数
}

func DefaultLimits() Limits {
	return Limits{MaxFileBytes: 64 << 20, MaxTotalBytes: 1 << 30, MaxEntries: 50000, MaxArchiveDepth: 2}
}

var scriptExts = map[string]bool{
	".bat": true, ".cmd": true, ".ps1": true, ".psm1": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".hta": true, ".py": true, ".sh": true, ".lnk": true,
}

var injectToolMarkers = []string{"prepare_vpet_mod", "vpetoneclick"}

type modMeta struct {
	name, author string
	isMod        bool
}

type walker struct {
	lim      Limits
	total    int64
	entries  int
	files    []string // 所有文件的展示路径，用于布局规则
	pes      []FileInfo
	findings []Finding
	mods     map[string]modMeta // MOD 根目录 → info.lps 元数据
	warnings []string
	stop     bool
}

func newWalker(lim Limits) *walker {
	return &walker{lim: lim, mods: map[string]modMeta{}}
}

// ScanPath 扫描本地目录、压缩包或单个文件。
func ScanPath(p string, lim Limits) (*Report, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	w := newWalker(lim)
	disp := filepath.ToSlash(filepath.Clean(p))
	if st.IsDir() {
		w.walkDir(p, disp)
	} else {
		if data := w.readFile(p, disp); data != nil {
			w.consume(disp, data, 0)
		}
	}
	return w.report(disp), nil
}

// ScanReader 扫描一个上传的文件（压缩包或单个 PE）。
func ScanReader(name string, r io.ReaderAt, size int64, lim Limits) *Report {
	w := newWalker(lim)
	if !w.budget(1) {
		return w.report(name)
	}
	data, err := io.ReadAll(io.LimitReader(io.NewSectionReader(r, 0, size), w.lim.MaxFileBytes+1))
	if err != nil {
		w.warn("%s: %v", name, err)
		return w.report(name)
	}
	if int64(len(data)) > w.lim.MaxFileBytes {
		w.warn("%s: 超过单文件上限 %d 字节，未分析", name, w.lim.MaxFileBytes)
		return w.report(name)
	}
	w.total += int64(len(data))
	w.consume(name, data, 0)
	return w.report(name)
}

// walkDir 遍历一个本地目录：先嗅探再决定是否整读，避免把无关的大文件读进内存。
func (w *walker) walkDir(root, disp string) {
	err := filepath.WalkDir(root, func(fp string, d os.DirEntry, err error) error {
		if err != nil {
			w.warn("%s: %v", fp, err)
			return nil
		}
		if w.stop {
			return filepath.SkipAll
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil // 不跟随符号链接/联接点
		}
		if !w.budget(1) {
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(root, fp)
		childDisp := join(disp, filepath.ToSlash(rel))
		w.files = append(w.files, childDisp)

		name := strings.ToLower(d.Name())
		if w.handleNamed(childDisp, name, func(max int64) []byte { return w.readFileMax(fp, childDisp, max) }) {
			return nil
		}
		// 嗅探头部：不信扩展名，改名成 .png 的 PE / 压缩包照样识别。
		head := w.peek(fp, 264)
		if archive.IsArchive(head) {
			if data := w.readFile(fp, childDisp); data != nil {
				w.walkArchive(childDisp, data, 1)
			}
			return nil
		}
		if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
			if data := w.readFile(fp, childDisp); data != nil {
				w.analyzePEBytes(childDisp, data)
			}
			return nil
		}
		// 文本类文件：提取配置里内嵌的外联地址/密钥（原生 PE 代码节看不到）。
		if isTextLike(head) {
			if data := w.readFileMax(fp, childDisp, textExtractMax); data != nil {
				w.analyzeTextBytes(childDisp, data)
			}
		}
		return nil
	})
	if err != nil {
		w.warn("%s: %v", disp, err)
	}
}

// consume 处理"已拿到完整字节"的一个成员（压缩包内成员，或顶层上传的单文件）。
func (w *walker) consume(disp string, data []byte, depth int) {
	w.files = append(w.files, disp)
	name := strings.ToLower(path.Base(disp))
	if w.handleNamed(disp, name, func(max int64) []byte { return clip(data, max) }) {
		return
	}
	if archive.IsArchive(data) {
		w.walkArchive(disp, data, depth+1)
		return
	}
	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		w.analyzePEBytes(disp, data)
		return
	}
	if isTextLike(clip(data, 264)) {
		w.analyzeTextBytes(disp, data)
	}
}

// handleNamed 处理靠文件名判定的三类文件（info.lps / .px_sidecar / 脚本）。
// read(max) 惰性取内容。命中返回 true。
func (w *walker) handleNamed(disp, name string, read func(max int64) []byte) bool {
	switch {
	case name == "info.lps":
		// 动画目录（pet/xxx/动作/info.lps）也叫 info.lps，只有带 vupmod 行的才是 MOD 根。
		if b := read(64 << 10); b != nil {
			if m := parseInfoLps(b); m.isMod {
				w.mods[path.Dir(disp)] = m
			}
		}
		return true
	case name == "info.ini":
		// 非 VPet 宿主的 MOD 清单（Unity/BepInEx 风格，如 鸭科夫假红信mod 的 info.ini
		// 带 name/displayName/publishedFileId）。家族已经在跨游戏投放，不认这类清单
		// 就会整包降级成 loose，审核页看不到"这是什么 MOD、作者是谁"。
		if b := read(64 << 10); b != nil {
			if m := parseInfoIni(b); m.isMod {
				w.mods[path.Dir(disp)] = m
			}
		}
		return true
	case name == ".px_sidecar":
		ev := map[string]string{}
		if b := read(64 << 10); b != nil {
			for _, ln := range strings.Split(string(b), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(ln), "="); ok {
					ev[k] = v
				}
			}
		}
		w.findings = append(w.findings, newFinding("PX-SIDECAR", disp, "", ev))
		return true
	case scriptExts[path.Ext(name)]:
		w.findings = append(w.findings, newFinding("MOD-SCRIPT", disp, "", nil))
		if b := read(1 << 20); b != nil {
			low := strings.ToLower(string(b))
			for _, m := range injectToolMarkers {
				if strings.Contains(low, m) {
					w.findings = append(w.findings, newFinding("MOD-INJECT-TOOLING", disp, "", map[string]string{"marker": m}))
					break
				}
			}
		}
		return true
	}
	return false
}

// walkArchive 解出压缩包一层的成员，逐个交回 consume。
func (w *walker) walkArchive(disp string, data []byte, depth int) {
	if depth > w.lim.MaxArchiveDepth {
		w.warn("%s: 压缩包嵌套超过 %d 层，未展开", disp, w.lim.MaxArchiveDepth)
		return
	}
	opt := archive.Options{
		MaxFileBytes: w.lim.MaxFileBytes,
		Warn:         func(f string, a ...any) { w.warn("%s!/"+f, append([]any{disp}, a...)...) },
	}
	_, err := archive.Walk(disp, data, opt, func(memberName string, md []byte) {
		if w.stop || !w.budget(1) {
			w.stop = true
			return
		}
		if !w.spend(int64(len(md))) {
			return
		}
		w.consume(disp+"!/"+cleanMember(memberName), md, depth)
	})
	if err != nil {
		w.warn("%s: 解压失败: %v", disp, err)
	}
}

func (w *walker) analyzePEBytes(disp string, data []byte) {
	fi, found := analyzePE(disp, data)
	w.pes = append(w.pes, fi)
	w.findings = append(w.findings, found...)
}

// resolveHelperTargets 丢掉"按名加载的原生 DLL 并不在本次扫描范围内"的 GEN-HELPER-NATIVE-EXEC。
//
// 为什么必须做包内解析：合法库同样会引用原生加载三件套并指名一个 DLL，完全不值得怀疑。
// 工坊 134 个 MOD 语料实测的假阳性（打补丁前都没有，是新增该规则引入的）：
//
//	CSCore.dll               -> X3DAudio1_7.dll                    （Windows 系统 DLL）
//	Microsoft.CodeAnalysis.dll -> Microsoft.DiaSymReader.Native.x86.dll（旁加载组件）
//	System.Management.dll    -> wminet_utils.dll                   （系统 DLL）
//
// 家族的特征不是"按名加载原生 DLL"，而是"加载**随包一起投放**的原生 DLL"：
// CalcBridge.dll -> SteamCFyinxiao.dll，两者同在一个 MOD 包里。
// 所以要求目标能在本次扫描的 PE 清单里解析到，才保留这条 medium。
func resolveHelperTargets(pes []FileInfo, fs []Finding) []Finding {
	if len(fs) == 0 {
		return fs
	}
	inPkg := make(map[string]bool, len(pes))
	for _, p := range pes {
		inPkg[strings.ToLower(pathBaseName(p.Path))] = true
	}
	out := fs[:0:0]
	for _, f := range fs {
		if f.Rule == "GEN-HELPER-NATIVE-EXEC" {
			t := strings.ToLower(pathBaseName(f.Evidence["target"]))
			if t == "" || !inPkg[t] {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// dedupeFindings 去掉完全相同的发现（同规则 + 同路径 + 同证据）。
//
// 为什么需要：同一条 IOC 可能被两条互相独立的路径各命中一次——例如 URL 形态的
// "https://bvdpp.top/ey/2.php" 会同时被 networkFindings（解析 URL）与 knownC2InBytes
// （原始字节找裸 host）报出来。计分按规则去重，分值不受影响，但报告里会出现两条一模一样的
// 记录，审核页看着像重复告警。这里统一压掉，保留首次出现顺序。
func dedupeFindings(fs []Finding) []Finding {
	if len(fs) < 2 {
		return fs
	}
	seen := make(map[string]bool, len(fs))
	out := fs[:0:0]
	for _, f := range fs {
		keys := make([]string, 0, len(f.Evidence))
		for k, v := range f.Evidence {
			keys = append(keys, k+"="+v)
		}
		sort.Strings(keys) // map 顺序随机，排序后 key 才稳定
		id := f.Rule + "|" + f.Path + "|" + strings.Join(keys, ",")
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, f)
	}
	return out
}

// 文本类文件的外联/密钥提取上限：配置/语言 JSON 通常几十~几百 KB，超大文本（日志）跳过。
const textExtractMax = 8 << 20

// isTextLike：头部无 NUL 且可打印占比高，视为文本。改扩展名骗不过，二进制也不会误判。
func isTextLike(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c >= 0x20 || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return printable*100/len(b) >= 85
}

// analyzeTextBytes 从文本类文件（json/lps/txt/conf/xml…）里提取外联地址与内嵌密钥。
// 配置文件里的端点和 API Key 是原生 PE #US 堆看不到的盲区——托管插件把 TTS/预设/推广地址
// 写进随包 JSON 时，只扫代码节会整片漏掉。低危提示为主，命中已知 C2 / 内嵌密钥才升级。
func (w *walker) analyzeTextBytes(disp string, data []byte) {
	if len(data) > textExtractMax || !isTextLike(data) {
		return
	}
	lines := strings.Split(string(data), "\n")
	w.findings = append(w.findings, networkFindingsX(disp, lines, false)...)
	// 丢弃的注入脚本 / JS 片段（例如落盘的 sp.js、px_msgpoll.js）也要能定性：
	// 与 PE 走同一套标记与裸域名取证。
	w.findings = append(w.findings, artifactMarkerFindings(disp, data)...)
	w.findings = append(w.findings, knownC2InBytes(disp, data)...)
}

// budget 检查文件数上限；超限置 stop 并只 warn 一次。
func (w *walker) budget(n int) bool {
	if w.stop {
		return false
	}
	w.entries += n
	if w.entries > w.lim.MaxEntries {
		w.warn("文件数超过上限 %d，后续未扫描", w.lim.MaxEntries)
		w.stop = true
		return false
	}
	return true
}

// spend 记账累计读入字节；超限置 stop 并只 warn 一次。
func (w *walker) spend(n int64) bool {
	if w.total+n > w.lim.MaxTotalBytes {
		if !w.stop {
			w.warn("累计读入超过上限 %d 字节，后续未扫描", w.lim.MaxTotalBytes)
		}
		w.stop = true
		return false
	}
	w.total += n
	return true
}

// peek 读文件头部 n 字节用于嗅探。
func (w *walker) peek(fp string, n int) []byte {
	f, err := os.Open(fp)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n)
	m, _ := io.ReadFull(f, buf)
	return buf[:m]
}

func (w *walker) readFile(fp, disp string) []byte { return w.readFileMax(fp, disp, w.lim.MaxFileBytes) }

func (w *walker) readFileMax(fp, disp string, max int64) []byte {
	if w.stop {
		return nil
	}
	f, err := os.Open(fp)
	if err != nil {
		w.warn("%s: %v", disp, err)
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		w.warn("%s: %v", disp, err)
		return nil
	}
	if int64(len(b)) > max {
		w.warn("%s: 超过 %d 字节上限，未分析", disp, max)
		return nil
	}
	if !w.spend(int64(len(b))) {
		return nil
	}
	return b
}

func (w *walker) warn(format string, a ...any) {
	w.warnings = append(w.warnings, fmt.Sprintf(format, a...))
}

// layoutFindings 跑依赖整个 MOD 目录结构的规则。
func (w *walker) layoutFindings(roots []string) {
	lower := make(map[string]string, len(w.files))
	for _, f := range w.files {
		lower[strings.ToLower(f)] = f
	}
	isPE := map[string]bool{}
	for _, p := range w.pes {
		isPE[p.Path] = true
	}

	for _, f := range w.files {
		lf := strings.ToLower(f)
		if !strings.HasSuffix(lf, ".orig.dll") || !strings.Contains(lf, "/plugin/") {
			continue
		}
		// plugin/lib/X.orig.dll ↔ plugin/X.dll
		dir := path.Dir(lf)
		base := strings.TrimSuffix(path.Base(lf), ".orig.dll") + ".dll"
		for _, cand := range []string{path.Join(path.Dir(dir), base), path.Join(dir, base)} {
			if orig, ok := lower[cand]; ok {
				w.findings = append(w.findings, newFinding("MOD-ORIG-WRAP", f, "", map[string]string{"wrapper": orig}))
				break
			}
		}
	}

	for _, root := range roots {
		nativePrefix := strings.ToLower(root) + "/native/"
		var dlls []string
		for _, f := range w.files {
			if strings.HasPrefix(strings.ToLower(f), nativePrefix) && isPE[f] {
				dlls = append(dlls, path.Base(f))
			}
		}
		if len(dlls) > 0 {
			w.findings = append(w.findings, newFinding("MOD-NATIVE-DIR", root+"/native", "",
				map[string]string{"dlls": strings.Join(dlls, ",")}))
		}
	}
}

func (w *walker) report(target string) *Report {
	roots := make([]string, 0, len(w.mods))
	for r := range w.mods {
		roots = append(roots, r)
	}
	w.layoutFindings(roots)
	w.findings = resolveHelperTargets(w.pes, w.findings)
	w.findings = dedupeFindings(w.findings)
	// 最长前缀优先，保证嵌套 MOD 归到最近的根。
	sort.Slice(roots, func(i, j int) bool { return len(roots[i]) > len(roots[j]) })

	byRoot := map[string][]Finding{}
	var loose []Finding
	for _, f := range w.findings {
		root, ok := ownerRoot(f.Path, roots)
		if ok {
			byRoot[root] = append(byRoot[root], f)
		} else {
			loose = append(loose, f)
		}
	}

	rep := &Report{Target: target, Files: w.pes, Scanned: w.entries, Warnings: w.warnings, Mods: []ModReport{}}
	if rep.Files == nil {
		rep.Files = []FileInfo{}
	}
	// 汇总静态提取的外联地址/密钥（来自 NET-* 发现），供网页「外联地址（静态）」直接展示。
	seenNI := map[string]bool{}
	for _, f := range w.findings {
		if f.Rule != "NET-ENDPOINT" && f.Rule != "NET-EMBEDDED-SECRET" && f.Rule != "NET-KNOWN-C2" {
			continue
		}
		for k, v := range f.Evidence {
			key := k + "|" + v
			if seenNI[key] {
				continue
			}
			seenNI[key] = true
			rep.NetworkIndicators = append(rep.NetworkIndicators, NetIndicator{Kind: k, Value: v, Path: f.Path})
		}
	}
	all := append([]Finding(nil), loose...)
	for _, r := range roots {
		found := byRoot[r]
		sortFindings(found)
		s := score(found)
		meta := w.mods[r]
		if found == nil {
			found = []Finding{}
		}
		rep.Mods = append(rep.Mods, ModReport{Root: r, Name: meta.name, Author: meta.author,
			Verdict: verdictOf(s, found), Score: s, Findings: found})
		all = append(all, found...)
	}
	sort.Slice(rep.Mods, func(i, j int) bool { return rep.Mods[i].Root < rep.Mods[j].Root })
	sortFindings(loose)
	rep.Loose = loose

	// 总分取最危险的那个分组，而不是全部相加：一个目录里 10 个干净 MOD 各带一个脚本不该变成"恶意"。
	worst := score(loose)
	for _, m := range rep.Mods {
		if m.Score > worst {
			worst = m.Score
		}
	}
	rep.Score = worst
	rep.Verdict = verdictOf(worst, all)
	if rep.Verdict == Clean {
		for _, m := range rep.Mods {
			if m.Verdict == Suspicious {
				rep.Verdict = Suspicious
			}
		}
	}
	return rep
}

func ownerRoot(p string, roots []string) (string, bool) {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return r, true
		}
	}
	return "", false
}

func join(prefix, p string) string {
	if p == "." || p == "" {
		return prefix
	}
	if prefix == "" {
		return p
	}
	return prefix + "/" + p
}

// cleanMember 归一化压缩包内成员路径：统一分隔符、去掉 ./ 与前导 /，挡住 ../ 逃逸展示。
func cleanMember(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" {
		return "_"
	}
	return name
}

func clip(data []byte, max int64) []byte {
	if int64(len(data)) > max {
		return data[:max]
	}
	return data
}

// parseInfoLps 只取 vupmod/author 两个字段，LPS 行格式为 key#value:|key#value:|
func parseInfoLps(b []byte) modMeta {
	var m modMeta
	s := strings.TrimPrefix(string(b), "\xef\xbb\xbf")
	for _, part := range strings.Split(s, ":|") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "#")
		if !ok {
			continue
		}
		switch k {
		case "vupmod":
			m.isMod = true
			if m.name == "" {
				m.name = v
			}
		case "author":
			if m.author == "" {
				m.author = v
			}
		}
	}
	return m
}

// parseInfoIni 认非 VPet 宿主的 MOD 清单（Unity/BepInEx 风格的 info.ini，形如
//
//	name = CFKillFeedback
//	displayName = ...
//	publishedFileId = 3792623130
//
// 只认同时带 name 与（publishedFileId | displayName | description）的，避免把随便一个
// info.ini 当成 MOD 根。name 优先用 displayName（人看的），author 无对应字段则留空。
func parseInfoIni(b []byte) modMeta {
	var m modMeta
	var name, display string
	var hasId, hasDisplay, hasDesc bool
	for _, ln := range strings.Split(strings.TrimPrefix(string(b), "\xef\xbb\xbf"), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "name":
			name = v
		case "displayname":
			display, hasDisplay = v, v != ""
		case "publishedfileid":
			hasId = v != ""
		case "description":
			hasDesc = v != ""
		case "author":
			m.author = v
		}
	}
	if name == "" || !(hasId || hasDisplay || hasDesc) {
		return m
	}
	m.isMod = true
	if display != "" {
		m.name = display
	} else {
		m.name = name
	}
	return m
}
