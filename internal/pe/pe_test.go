package pe

import (
	"strings"
	"testing"
)

func TestStringsASCII(t *testing.T) {
	// minLen=6：5 个字符的 "short" 必须被过滤掉。
	got := Strings([]byte("\x00\x01hello world\x00\x02ab\x00short\x00"), 6)
	want := map[string]bool{"hello world": true}
	for _, s := range got {
		if !want[s] {
			t.Errorf("不该抽出 %q", s)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %q", got)
	}
}

// 宽字符（UTF-16LE）串必须能抽出来——Windows 原生载荷大量使用宽字符。
func TestStringsUTF16LE(t *testing.T) {
	var b []byte
	b = append(b, 0x00, 0x00) // 让串起始于奇数偏移，检验不依赖对齐
	for _, r := range "bvdpp.top" {
		b = append(b, byte(r), 0x00)
	}
	b = append(b, 0xDE, 0xAD)
	got := Strings(b, 5)
	found := false
	for _, s := range got {
		if s == "bvdpp.top" {
			found = true
		}
	}
	if !found {
		t.Fatalf("未抽出 UTF-16LE 串，got %q", got)
	}
}

func TestStringsDedupesAndObeysMinLen(t *testing.T) {
	got := Strings([]byte("aaaa\x00aaaa\x00aaa\x00"), 4)
	if len(got) != 1 || got[0] != "aaaa" {
		t.Fatalf("应去重且过滤短串，got %q", got)
	}
}

// 超长可打印段按窗切分：跨窗的 URL 不能因为被截断而丢掉。
func TestStringsLongRunIsWindowed(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(strings.Repeat("A", maxStrBytes+1000))
	sb.WriteString("https://bvdpp.top/gate.php")
	got := Strings([]byte(sb.String()), 6)
	found := false
	for _, s := range got {
		if strings.Contains(s, "https://bvdpp.top/gate.php") {
			found = true
		}
	}
	if !found {
		t.Fatalf("长段切窗后应仍能拿到段尾的 URL，抽出 %d 条", len(got))
	}
	for _, s := range got {
		if len(s) > maxStrBytes {
			t.Fatalf("单条长度 %d 超过上限 %d", len(s), maxStrBytes)
		}
	}
}

func TestArtifactRelevantStringsSurviveExtraction(t *testing.T) {
	// 模拟一份明态载荷：标记串散落在二进制里，混着宽字符。
	var b []byte
	for _, s := range []string{"/*px:b*/", "prefix", "_local_patch_backup", "tail"} {
		b = append(b, []byte(s)...)
		b = append(b, 0x00, 0x00, 0xFF)
	}
	for _, r := range "hhfyuxuz.top" {
		b = append(b, byte(r), 0x00)
	}
	b = append(b, 0x00, 0x00)
	got := Strings(b, 6)
	joined := strings.Join(got, "\n")
	for _, want := range []string{"/*px:b*/", "_local_patch_backup", "hhfyuxuz.top"} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少 %q；抽出：%q", want, got)
		}
	}
}
