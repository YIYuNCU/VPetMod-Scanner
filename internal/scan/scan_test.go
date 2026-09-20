package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 样本目录在仓库外（D:\CodeDesk\VPetLLM\Test），不存在就跳过。
const samplesDir = "../../../Test"

func requireSamples(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(samplesDir); err != nil {
		t.Skip("样本目录不存在，跳过")
	}
}

// PxBridge 家族的三个样本（目录名/zip 名）必须判恶意；其它样本（如托管插件对照样本）不在此断言内。
var pxbridgeRoots = []string{"3803401951", "depot_1920960_3678898894967785038", "depot_1920960_4637760495230589419"}

func isPxbridge(root string) bool {
	for _, r := range pxbridgeRoots {
		if strings.Contains(root, r) {
			return true
		}
	}
	return false
}

func TestSamplesMalicious(t *testing.T) {
	requireSamples(t)
	rep, err := ScanPath(samplesDir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range rep.Mods {
		if !isPxbridge(m.Root) {
			continue
		}
		n++
		if m.Verdict != Malicious {
			t.Errorf("%s: verdict=%s", m.Root, m.Verdict)
		}
	}
	if n < 6 { // 3 目录 + 3 zip
		t.Fatalf("PxBridge 样本数=%d，应至少 6（目录+zip）", n)
	}
}

// 清空全部哈希 IOC 后仍须判恶意：换密钥/换文件名重新打包的变种只能靠结构特征抓。
func TestSamplesDetectedWithoutHashes(t *testing.T) {
	requireSamples(t)
	saved := [3]map[string]string{iocFileSHA256, iocBodySHA256, iocTextSHA256}
	iocFileSHA256, iocBodySHA256, iocTextSHA256 = map[string]string{}, map[string]string{}, map[string]string{}
	defer func() { iocFileSHA256, iocBodySHA256, iocTextSHA256 = saved[0], saved[1], saved[2] }()

	rep, err := ScanPath(samplesDir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range rep.Mods {
		if !isPxbridge(m.Root) {
			continue
		}
		rules := map[string]bool{}
		for _, f := range m.Findings {
			rules[f.Rule] = true
			if strings.HasPrefix(f.Rule, "IOC-") {
				t.Errorf("IOC 已清空却命中 %s", f.Rule)
			}
		}
		if m.Verdict != Malicious {
			t.Errorf("%s: verdict=%s", m.Root, m.Verdict)
		}
		for _, want := range []string{"PX-BOOT-EXPORT", "PX-BOOT-TRAILER", "PX-PAYLOAD", "PX-PAYLOAD-TRAILER", "PX-STUB"} {
			if !rules[want] {
				t.Errorf("%s: 缺少 %s", m.Root, want)
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
	p := filepath.Join(samplesDir, "3803401951", "native", "gamev47.dll")
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
	p := filepath.Join(samplesDir, "depot_1920960_4637760495230589419", "plugin", "VPet.Plugin.TianLaiZhiYin.dll")
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
	src := filepath.Join(samplesDir, "depot_1920960_4637760495230589419")
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
