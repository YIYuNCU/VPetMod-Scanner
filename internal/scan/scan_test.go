package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpetmod-scanner/internal/pe"
)

// 样本目录默认是仓库上一级的 样本库/（即 VPetMod-Scanner/../），可用 VPETSCAN_SAMPLES 覆盖。
//
// 之前写死 "../../../Test"，那个目录不存在，于是 go test ./... 虽然全绿，但**全部样本断言
// 都被 t.Skip 掉了**——"改规则 -> 跑测试"这条保护链是断的。改成真实路径后断言才真的执行。
func samplesDir() string {
	if v := os.Getenv("VPETSCAN_SAMPLES"); v != "" {
		return v
	}
	return "../../../"
}

func requireSamples(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(samplesDir()); err != nil {
		t.Skipf("样本目录 %s 不存在，跳过（用 VPETSCAN_SAMPLES 指定）", samplesDir())
	}
}

// PxBridge 家族的三个 VPet 投放包：目录与 zip 各一份。
// 显式列举而不是整目录遍历——样本库根下还有 _analysis/、.build-vpetscan/ 等分析产物，
// 整目录扫既慢又会把评测工具自己的文件当成样本。
var pxbridgeRoots = []string{
	"3803401951", "3803401951.zip",
	"depot_1920960_3678898894967785038", "depot_1920960_3678898894967785038.zip",
	"depot_1920960_4637760495230589419", "depot_1920960_4637760495230589419.zip",
}

func isPxbridge(root string) bool {
	for _, r := range pxbridgeRoots {
		if strings.Contains(root, r) {
			return true
		}
	}
	return false
}

func samplePath(rel string) string { return filepath.Join(samplesDir(), rel) }

// scanSample 扫一个样本目标；不存在则 skip 当前用例。
func scanSample(t *testing.T, rel string) *Report {
	t.Helper()
	requireSamples(t)
	p := samplePath(rel)
	rep, err := ScanPath(p, DefaultLimits())
	if err != nil {
		t.Skipf("%s: %v", p, err)
	}
	return rep
}

func rulesOf(rep *Report) map[string]bool {
	rules := map[string]bool{}
	for _, m := range rep.Mods {
		for _, f := range m.Findings {
			rules[f.Rule] = true
		}
	}
	for _, f := range rep.Loose {
		rules[f.Rule] = true
	}
	return rules
}

func TestSamplesMalicious(t *testing.T) {
	requireSamples(t)
	n := 0
	for _, rel := range pxbridgeRoots {
		if _, err := os.Stat(samplePath(rel)); err != nil {
			continue
		}
		n++
		rep := scanSample(t, rel)
		if rep.Verdict != Malicious {
			t.Errorf("%s: verdict=%s score=%d", rel, rep.Verdict, rep.Score)
		}
	}
	if n < 6 {
		t.Fatalf("PxBridge 样本数=%d，应至少 6（3 目录 + 3 zip）", n)
	}
}

// 清空全部哈希 IOC 后仍须判恶意：换密钥/换文件名重新打包的变种只能靠结构特征抓。
func TestSamplesDetectedWithoutHashes(t *testing.T) {
	requireSamples(t)
	saved := [3]map[string]string{iocFileSHA256, iocBodySHA256, iocTextSHA256}
	iocFileSHA256, iocBodySHA256, iocTextSHA256 = map[string]string{}, map[string]string{}, map[string]string{}
	defer func() { iocFileSHA256, iocBodySHA256, iocTextSHA256 = saved[0], saved[1], saved[2] }()

	need := []string{"PX-BOOT-EXPORT", "PX-BOOT-TRAILER", "PX-PAYLOAD", "PX-PAYLOAD-TRAILER", "PX-STUB"}
	for _, rel := range pxbridgeRoots {
		if _, err := os.Stat(samplePath(rel)); err != nil {
			continue
		}
		rep := scanSample(t, rel)
		rules := rulesOf(rep)
		for r := range rules {
			if strings.HasPrefix(r, "IOC-") {
				t.Errorf("%s: IOC 已清空却命中 %s", rel, r)
			}
		}
		if rep.Verdict != Malicious {
			t.Errorf("%s: verdict=%s", rel, rep.Verdict)
		}
		for _, want := range need {
			if !rules[want] {
				t.Errorf("%s: 缺少 %s", rel, want)
			}
		}
	}
}

func TestManagedPluginNetworkExtraction(t *testing.T) {
	strs := []string{
		"https://api.ltzy.top/v1/chat/completions",
		"Bearer", "sk-b269d43a27cceca1b5259dbab6e679029333bd1ce98fd6c8",
		"just text",
	}
	fs := networkFindings("p.dll", strs)
	var url, secret bool
	for _, f := range fs {
		if f.Rule == "NET-ENDPOINT" && f.Evidence["url"] == "https://api.ltzy.top/v1/chat/completions" {
			url = true
		}
		if f.Rule == "NET-EMBEDDED-SECRET" {
			secret = true
			if strings.Contains(f.Evidence["secret"], "b269d43a27cceca1b5259dbab6e679029333bd1ce98fd6c8") {
				t.Error("密钥应打码而非全量输出")
			}
		}
	}
	if !url || !secret {
		t.Fatalf("url=%v secret=%v", url, secret)
	}
}

// 3803426816 载荷解密证实的 C2：任何文件明文里出现（子域名也算）都必须升级 NET-KNOWN-C2。
func TestKnownC2Upgrade(t *testing.T) {
	fs := networkFindings("p.dll", []string{
		"https://bvdpp.top/ey/2.php",
		"https://C2.BVDPP.TOP/vdf/2.php",
		"https://api.ltzy.top/v1/chat/completions", // 非 C2，保持 NET-ENDPOINT
	})
	var c2, plain int
	for _, f := range fs {
		switch f.Rule {
		case "NET-KNOWN-C2":
			c2++
		case "NET-ENDPOINT":
			plain++
		}
	}
	if c2 != 2 {
		t.Fatalf("bvdpp.top 主域+子域应各命中一次 NET-KNOWN-C2，got %d（%+v）", c2, fs)
	}
	if plain != 1 {
		t.Fatalf("普通端点应保持 NET-ENDPOINT，got %d", plain)
	}
	if s := verdictOf(score(fs), fs); s != Malicious {
		t.Fatalf("命中已知 C2 应直接判恶意，got %s", s)
	}
}

// 单个加密载荷文件（无 boot、无桩、无目录上下文）也要靠自身 trailer 与明文标记定性。
func TestLoosePayloadDetected(t *testing.T) {
	requireSamples(t)
	p := samplePath("3803401951/native/gamev47.dll")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skip(err)
	}
	rep := ScanReader("gamev47.dll", bytes.NewReader(b), int64(len(b)), DefaultLimits())
	rules := map[string]bool{}
	for _, f := range rep.Loose {
		rules[f.Rule] = true
	}
	for _, want := range []string{"PX-PAYLOAD-TRAILER", "PX-JS-INJECT"} {
		if !rules[want] {
			t.Errorf("缺少 %s（命中：%v）", want, rules)
		}
	}
	if rep.Verdict != Malicious {
		t.Fatalf("verdict=%s", rep.Verdict)
	}
}

// 连家族标记都被改名的"通用变种"：只剩行为/布局规则，也要能叠加到恶意。
func TestGenericScoringReachesMalicious(t *testing.T) {
	fs := []Finding{
		newFinding("GEN-STUB-NATIVE-EXEC", "p", "", nil),
		newFinding("GEN-STUB-REFLECT-ORIG", "p", "", nil),
		newFinding("MOD-ORIG-WRAP", "p", "", nil),
		newFinding("MOD-NATIVE-DIR", "p", "", nil),
	}
	if s := score(fs); verdictOf(s, fs) != Malicious {
		t.Fatalf("score=%d verdict=%s", s, verdictOf(s, fs))
	}
	// Harmony/MonoMod 类正常 MOD 只会命中这一条，必须保持干净。
	one := fs[:1]
	if v := verdictOf(score(one), one); v != Clean {
		t.Fatalf("单条 GEN-STUB-NATIVE-EXEC 判成了 %s", v)
	}
}

func TestScoreDedupByRule(t *testing.T) {
	var fs []Finding
	for i := 0; i < 20; i++ {
		fs = append(fs, newFinding("MOD-SCRIPT", "x", "", nil))
	}
	if s := score(fs); s != Low.Score() {
		t.Fatalf("同一规则应只计一次，got %d", s)
	}
}

func TestBootTrailer(t *testing.T) {
	ov := make([]byte, 44)
	copy(ov[8:], "gamev47.dll")
	copy(ov[24:], "msgame2.dll")
	binary.LittleEndian.PutUint32(ov[40:], 40)
	ev, ok := bootTrailer(ov)
	if !ok || ev["mod1"] != "gamev47.dll" || ev["mod2"] != "msgame2.dll" {
		t.Fatalf("got %v %v", ev, ok)
	}
	copy(ov[24:], "\x01\x02garbage\x00")
	if _, ok := bootTrailer(ov); ok {
		t.Fatal("非法文件名不应命中")
	}
}

func TestParseInfoLps(t *testing.T) {
	m := parseInfoLps([]byte("\xef\xbb\xbfvupmod#刮刮卡:|author#步眠:|gamever#11071:|ver#104:|\nintro#x:|"))
	if m.name != "刮刮卡" || m.author != "步眠" {
		t.Fatalf("%+v", m)
	}
}

func TestZipLimits(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("mod/info.lps")
	w.Write([]byte("vupmod#bomb:|"))
	w, _ = zw.Create("mod/plugin/big.dll")
	w.Write(append([]byte("MZ"), make([]byte, 4<<20)...)) // 高压缩比
	zw.Close()

	lim := DefaultLimits()
	lim.MaxFileBytes = 1 << 20
	rep := ScanReader("bomb.zip", bytes.NewReader(buf.Bytes()), int64(buf.Len()), lim)
	if len(rep.Warnings) == 0 {
		t.Fatal("超限文件应产生 warning")
	}
	if rep.Verdict != Clean {
		t.Fatalf("verdict=%s", rep.Verdict)
	}
}

func TestNestedZipDepth(t *testing.T) {
	inner := func(data []byte, name string) []byte {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		w, _ := zw.Create(name)
		w.Write(data)
		zw.Close()
		return b.Bytes()
	}
	z := inner([]byte("x"), "a.txt")
	for i := 0; i < 5; i++ {
		z = inner(z, "n.zip")
	}
	rep := ScanReader("deep.zip", bytes.NewReader(z), int64(len(z)), DefaultLimits())
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "嵌套") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应提示嵌套超限: %v", rep.Warnings)
	}
}

func TestSingleUploadedStub(t *testing.T) {
	requireSamples(t)
	p := samplePath("depot_1920960_4637760495230589419/plugin/VPet.Plugin.TianLaiZhiYin.dll")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skip(err)
	}
	rep := ScanReader("x.dll", bytes.NewReader(b), int64(len(b)), DefaultLimits())
	if rep.Verdict != Malicious || len(rep.Loose) == 0 {
		t.Fatalf("verdict=%s loose=%d", rep.Verdict, len(rep.Loose))
	}
}

// 把恶意样本重打包成 tar.gz，验证压缩包解包路径与 zip 等效。
func TestTarGzDetected(t *testing.T) {
	requireSamples(t)
	src := samplePath("depot_1920960_4637760495230589419")
	if _, err := os.Stat(src); err != nil {
		t.Skip("样本不存在")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		rel, _ := filepath.Rel(src, p)
		tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
		return nil
	})
	tw.Close()
	gz.Close()

	rep := ScanReader("sample.tar.gz", bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultLimits())
	if rep.Verdict != Malicious {
		t.Fatalf("tar.gz verdict=%s", rep.Verdict)
	}
}

// ---------------------------------------------------------------- 新增回归
//
// 以下用例对应 2026-09 评测发现的缺口（详见 _analysis/VPetMod-Scanner_家族检测能力评估.md）：
//   1. 明态编译载荷 SteamCFyinxiao.dll（跨游戏投放）在 .rdata 里有 12 个家族标记，
//      但 PX-JS-INJECT 只搜 .text 的 3 个标记，整包只靠 "__pxGate" 一个字符串定性；
//   2. 原生 PE 完全不提取字符串，"明文出现已知 C2 即判恶意"不成立；
//   3. 载荷在磁盘上只存裸 host，urlRe 要求 scheme，永远匹配不到；
//   4. 非插件入口的辅助程序集（CalcBridge.dll）在 MainPlugin 检查后提前返回，整条漏掉。

const duckZip = "鸭科夫假红信mod.zip"
const duckInner = "鸭科夫假红信mod/鸭科夫假红信mod/"

func duckMember(t *testing.T, name string) []byte {
	t.Helper()
	requireSamples(t)
	zr, err := zip.OpenReader(samplePath(duckZip))
	if err != nil {
		t.Skipf("%s: %v", duckZip, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, name) {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Skipf("%s 里没有 %s", duckZip, name)
	return nil
}

// 明态载荷必须被检出，且不能只靠 PX-JS-INJECT 这一个通用性很差的字符串。
func TestPlaintextPayloadDetected(t *testing.T) {
	rep := scanSample(t, duckZip)
	rules := rulesOf(rep)
	if rep.Verdict != Malicious {
		t.Fatalf("verdict=%s score=%d", rep.Verdict, rep.Score)
	}
	if !rules["PX-ARTIFACT-MARKERS"] {
		t.Errorf("缺少 PX-ARTIFACT-MARKERS（命中：%v）", rules)
	}
	// info.ini 也应被认成 MOD 根，否则整包降级成 loose、审核页显示不出 MOD 名。
	if len(rep.Mods) == 0 {
		t.Fatal("info.ini 未建立 MOD 根，全部落进 loose")
	}
	if rep.Mods[0].Name == "" {
		t.Errorf("MOD 名未解析：%+v", rep.Mods[0])
	}
}

// 把 __pxGate 抹掉后仍须判恶意——这正是本次修复的验收条件。
func TestPlaintextPayloadWithoutGateMarker(t *testing.T) {
	data := duckMember(t, "SteamCFyinxiao.dll")
	if !bytes.Contains(data, []byte("__pxGate")) {
		t.Skip("样本已无 __pxGate，跳过")
	}
	wiped := bytes.ReplaceAll(data, []byte("__pxGate"), []byte("__qxHole"))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(duckInner + "SteamCFyinxiao.dll")
	w.Write(wiped)
	zw.Close()

	rep := ScanReader("wiped.zip", bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultLimits())
	rules := map[string]bool{}
	for _, f := range rep.Loose {
		rules[f.Rule] = true
	}
	if rules["PX-JS-INJECT"] {
		t.Error("__pxGate 已抹掉却仍命中 PX-JS-INJECT")
	}
	if !rules["PX-ARTIFACT-MARKERS"] {
		t.Errorf("抹掉 __pxGate 后应仍由 PX-ARTIFACT-MARKERS 定性，命中：%v", rules)
	}
	if rep.Verdict != Malicious {
		t.Fatalf("抹掉 __pxGate 后 verdict=%s score=%d（这正是修复前漏检的场景）", rep.Verdict, rep.Score)
	}
}

// 非入口辅助程序集按名加载原生 DLL：修复前这条链一条发现都没有。
//
// 注意这里断言的是"目标必须在同一个包里"——这是 134 MOD 语料回归后加上的精度条件：
// 合法库（CSCore、Microsoft.CodeAnalysis、System.Management）同样引用原生加载三件套，
// 但它们加载的是系统/旁加载 DLL，不在包内；家族加载的是随包投放的 native 载荷。
func TestHelperAssemblyNativeLoad(t *testing.T) {
	// 整包扫描：CalcBridge 加载的 SteamCFyinxiao.dll 就在同一个包里 -> 命中
	rep := scanSample(t, duckZip)
	var got string
	for _, m := range rep.Mods {
		for _, f := range m.Findings {
			if f.Rule == "GEN-HELPER-NATIVE-EXEC" {
				got = f.Evidence["target"]
			}
		}
	}
	if got == "" {
		t.Fatalf("整包扫描应命中 GEN-HELPER-NATIVE-EXEC")
	}
	if !strings.Contains(got, "SteamCFyinxiao") {
		t.Errorf("加载目标应为 SteamCFyinxiao.dll，got %q", got)
	}

	// 单独扫 CalcBridge.dll：目标不在扫描范围内，不得凭"引用了三个 API"就报
	// （那正是 CSCore -> X3DAudio1_7.dll 那类假阳性）。
	data := duckMember(t, "CalcBridge.dll")
	solo := ScanReader("CalcBridge.dll", bytes.NewReader(data), int64(len(data)), DefaultLimits())
	for _, f := range solo.Loose {
		if f.Rule == "GEN-HELPER-NATIVE-EXEC" {
			t.Fatalf("目标不在包内时不应命中：%+v", f)
		}
	}
}

// 命名空间/标识符类 URL 不进 NET-ENDPOINT；真实端点与已知 C2 不受影响。
func TestURIOnlyHostsFiltered(t *testing.T) {
	fs := networkFindings("x.dll", []string{
		"http://www.w3.org/2000/xmlns/",
		"http://james.newtonking.com/projects/json",
		"http://purl.org/dc/elements/1.1/",
		"http://example.com/api",
		"https://api.openai.com/v1",
		"https://vpetllm.ycxom.com/api/",
		"https://bvdpp.top/ey/2.php",
	})
	var endpoints, c2 []string
	for _, f := range fs {
		switch f.Rule {
		case "NET-ENDPOINT":
			endpoints = append(endpoints, f.Evidence["url"])
		case "NET-KNOWN-C2":
			c2 = append(c2, f.Evidence["host"])
		}
	}
	if len(c2) != 1 || c2[0] != "bvdpp.top" {
		t.Fatalf("已知 C2 不得被降噪过滤掉，got %v", c2)
	}
	want := map[string]bool{"https://api.openai.com/v1": true, "https://vpetllm.ycxom.com/api/": true}
	if len(endpoints) != len(want) {
		t.Fatalf("只应保留真实端点，got %v", endpoints)
	}
	for _, u := range endpoints {
		if !want[u] {
			t.Errorf("不该保留 %s", u)
		}
	}
}

// 版本号式 IP（4.0.0.0 这类，工坊语料里出现 19 次）、网络地址、以及 ASN.1 OID 片段
// 都不得算作外联 IP。
func TestVersionLikeIPRejected(t *testing.T) {
	for _, ip := range []string{"4.0.0.0", "123.0.0.0", "13.0.0.0", "0.1.2.3", "1.0.0.0", "999.1.1.1"} {
		if plausibleIP(ip) {
			t.Errorf("%s 不应被当成外联 IP", ip)
		}
	}
	for _, ip := range []string{"1.2.3.4", "203.0.113.7", "8.8.8.8"} {
		if !plausibleIP(ip) {
			t.Errorf("%s 应保留", ip)
		}
	}
	// OID 前缀是更长点分数字串的一截时整条不该出 IP
	// （工坊语料里 1.3.6.1 ×10、2.5.4.15 ×9 都是这样被误报的，修复后归零）。
	for _, s := range []string{"2.5.4.15.1", "1.3.6.1.4.1.311.10.3.4", "1.2.840.113549.1.1.11"} {
		for _, f := range networkFindings("x.dll", []string{s}) {
			if f.Rule == "NET-ENDPOINT" {
				t.Errorf("OID %q 不该产生 NET-ENDPOINT：%+v", s, f)
			}
		}
	}
	// 已知取舍：**孤立**的四段点分串（"2.5.4.15"）与真实 IP 无法区分，仍会作为 low 线索报出。
	// 属于 NET-ENDPOINT(low) 的可接受噪声，不影响判定（同规则在 MOD 内只计 5 分一次）。
	if fs := networkFindings("x.dll", []string{"2.5.4.15"}); len(fs) != 1 {
		t.Errorf("孤立四段串的行为变了，需要重新评估：%+v", fs)
	}
	// 独立出现的公网 IP 仍要抓到。
	found := false
	for _, f := range networkFindings("x.dll", []string{"connect 203.0.113.7:8443 now"}) {
		if f.Rule == "NET-ENDPOINT" && f.Evidence["ip"] != "" {
			found = true
		}
	}
	if !found {
		t.Error("独立出现的 IP 应保留")
	}
}

// 防回归：.fptable 是 Universal CRT 的函数指针缓存节（Windows SDK >= 10.0.26100），
// 不是打包器/家族指纹。工坊 134 MOD 语料里 3 个正常 MOD 因此被判可疑，规则已删除。
func TestFptableIsNotARule(t *testing.T) {
	for _, r := range Rules {
		if strings.Contains(r.ID, "FPTABLE") || strings.Contains(r.Title, "fptable") {
			t.Fatalf("PX-PACKER-FPTABLE 及其同类规则不得存在（.fptable 是 UCRT 产物）：%+v", r)
		}
	}
	if _, ok := ruleIndex["PX-PACKER-FPTABLE"]; ok {
		t.Fatal("PX-PACKER-FPTABLE 仍在规则表里")
	}
}

// resolveHelperTargets 的直测：目标解析不到就丢掉，解析得到就保留。
func TestResolveHelperTargets(t *testing.T) {
	pes := []FileInfo{
		{Path: "mod.zip!/mod/native/payload.dll"},
		{Path: "mod.zip!/mod/plugin/Bridge.dll"},
	}
	fs := []Finding{
		newFinding("GEN-HELPER-NATIVE-EXEC", "a", "", map[string]string{"target": "payload.dll"}),
		newFinding("GEN-HELPER-NATIVE-EXEC", "b", "", map[string]string{"target": "X3DAudio1_7.dll"}),
		newFinding("PX-STUB", "c", "", nil),
	}
	out := resolveHelperTargets(pes, fs)
	if len(out) != 2 {
		t.Fatalf("应保留 2 条（包内目标 + 无关规则），got %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.Rule == "GEN-HELPER-NATIVE-EXEC" && f.Evidence["target"] != "payload.dll" {
			t.Fatalf("包外目标未被丢掉：%+v", f)
		}
	}
}

// externalDllString 必须跳过自身模块名，否则任何引用原生加载三件套的辅助程序集都会误报。
func TestExternalDllStringSkipsSelf(t *testing.T) {
	info := &pe.Info{UserStrings: []string{"CalcBridge.dll", "SteamCFyinxiao.dll"}}
	if got := externalDllString("mod/CalcBridge.dll", info); got != "SteamCFyinxiao.dll" {
		t.Fatalf("应跳过自身名取外部 DLL，got %q", got)
	}
	if got := externalDllString("mod/CalcBridge.dll", &pe.Info{UserStrings: []string{"CalcBridge.dll"}}); got != "" {
		t.Fatalf("只有自身名时应返回空，got %q", got)
	}
}

// 载荷把 URL 存成 printf 模板时必须跳过：host 位是 "%s" 不是外联地址。
func TestURLTemplateHostSkipped(t *testing.T) {
	fs := networkFindings("x.dll", []string{
		"https://%s/gate.php",
		"https://%s/steamhelper?d=%s&a=%s",
		"https://cdn.realhost.net/api",
	})
	var urls []string
	for _, f := range fs {
		if f.Rule == "NET-ENDPOINT" {
			urls = append(urls, f.Evidence["url"])
		}
	}
	if len(urls) != 1 || urls[0] != "https://cdn.realhost.net/api" {
		t.Fatalf("只应保留真实地址，got %v", urls)
	}
}

// 已知 C2 的裸 host 必须能在原始字节里被认出来（ASCII 与 UTF-16LE 两种编码）。
func TestKnownC2InRawBytes(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"ascii 裸 host", []byte("host = bvdpp.top\n")},
		{"ascii UTF-16LE 裸 host", func() []byte {
			var b bytes.Buffer
			for _, r := range "hhfyuxuz.top" {
				b.WriteByte(byte(r))
				b.WriteByte(0)
			}
			return b.Bytes()
		}()},
		{"模板形式（host 与 URL 分离）", []byte("bvdpp.top\x00https://%s/gate.php")},
	}
	for _, c := range cases {
		fs := knownC2InBytes("x.dll", c.data)
		if len(fs) == 0 || fs[0].Rule != "NET-KNOWN-C2" {
			t.Errorf("%s: 应命中 NET-KNOWN-C2，got %+v", c.name, fs)
			continue
		}
		if verdictOf(score(fs), fs) != Malicious {
			t.Errorf("%s: 应判恶意", c.name)
		}
	}
	// 负例：不带 scheme 的普通域名、以及完全无关的内容都不能命中。
	for _, s := range []string{"https://api.ltzy.top/v1/chat", "example.com/path", "\x00\x01\x02"} {
		if fs := knownC2InBytes("x.dll", []byte(s)); len(fs) != 0 {
			t.Errorf("%q 不应命中已知 C2：%+v", s, fs)
		}
	}
}

// 工件标记的阈值：>=3 命中且至少 1 个强标记才 critical；弱标记凑数不能定性。
func TestArtifactMarkerThreshold(t *testing.T) {
	strong := []byte("/*px:b*/ _local_patch_backup px_msgpoll.js")
	if fs := artifactMarkerFindings("x.dll", strong); len(fs) != 1 || fs[0].Rule != "PX-ARTIFACT-MARKERS" {
		t.Fatalf("3 个强标记应判 PX-ARTIFACT-MARKERS，got %+v", fs)
	}
	// 只有弱标记，哪怕凑够 3 个也不能定性。
	weak3 := []byte("/gate.php /steamhelper api/messages")
	if fs := artifactMarkerFindings("x.dll", weak3); len(fs) != 1 || fs[0].Rule != "PX-ARTIFACT-MARKERS-WEAK" {
		t.Fatalf("纯弱标记应只给线索，got %+v", fs)
	}
	// 正常 Steam 相关内容（ConnectCache + api/messages）不得触发。
	benign := []byte("ConnectCache api/messages https://steamcommunity.com/")
	fs := artifactMarkerFindings("x.dll", benign)
	if len(fs) == 0 {
		return // 允许无命中
	}
	if fs[0].Rule != "PX-ARTIFACT-MARKERS-WEAK" || fs[0].Severity != Low {
		t.Fatalf("正常 Steam 内容不得升级为 %s/%s", fs[0].Rule, fs[0].Severity)
	}
}

// 弱标记命中只加 5 分，绝不能把干净文件推过阈值。
func TestArtifactWeakMarkerCannotReachSuspicious(t *testing.T) {
	fs := artifactMarkerFindings("x.dll", []byte("/gate.php api/messages"))
	if s := score(fs); verdictOf(s, fs) != Clean {
		t.Fatalf("弱线索判成了 %s（score=%d）", verdictOf(s, fs), s)
	}
}

// 误报守门：已知的导入表误报样本（媒体工具）必须保持干净。
func TestBenignMediaToolStaysClean(t *testing.T) {
	rep := scanSample(t, "depot_1920960_4637760495230589419/plugin/bin/SMTC.exe")
	if rep.Verdict != Clean {
		t.Fatalf("SMTC.exe 应判干净，got %s score=%d findings=%+v", rep.Verdict, rep.Score, rep.Loose)
	}
}

// info.ini（非 VPet 宿主）也必须能建立 MOD 根。
func TestParseInfoIni(t *testing.T) {
	m := parseInfoIni([]byte("name = CFKillFeedback\ndisplayName = CF 击杀音效\n" +
		"description = x\nversion = 1\ntags = Quality of Life\n\npublishedFileId = 3792623130\n"))
	if !m.isMod || m.name != "CF 击杀音效" {
		t.Fatalf("%+v", m)
	}
	// 缺 name 或缺标识字段的 info.ini 不算 MOD 根。
	if m := parseInfoIni([]byte("foo = bar\n")); m.isMod {
		t.Fatalf("无关 info.ini 不应被当成 MOD 根：%+v", m)
	}
	if m := parseInfoIni([]byte("name = x\n")); m.isMod {
		t.Fatalf("只有 name、没有标识字段时不应建立 MOD 根：%+v", m)
	}
}

// 重复发现要压掉：同一 C2 既可能被 URL 规则报出，也可能被裸字节规则报出。
func TestDedupeFindings(t *testing.T) {
	a := newFinding("NET-KNOWN-C2", "p", "note", map[string]string{"host": "bvdpp.top"})
	b := newFinding("NET-KNOWN-C2", "p", "note", map[string]string{"host": "bvdpp.top"})
	c := newFinding("NET-KNOWN-C2", "p", "note", map[string]string{"url": "https://bvdpp.top/gate.php"})
	out := dedupeFindings([]Finding{a, b, c})
	if len(out) != 2 {
		t.Fatalf("应压成 2 条（同证据合并且不同证据保留），got %d", len(out))
	}
}
