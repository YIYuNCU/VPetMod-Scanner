package worker

import (
	"testing"

	"vpetmod-scanner/internal/scan"
)

// 结构命中时，引爆目标取 boot/载荷路径，不走原生 PE 兜底。
func TestDetonationTargetStructural(t *testing.T) {
	rep := &scan.Report{
		Files: []scan.FileInfo{
			{Path: "m!/native/x.dll", Kind: "pe-native"},
		},
		Loose: []scan.Finding{{Rule: "PX-BOOT-EXPORT", Path: "m!/native/boot.dll"}},
	}
	if got := DetonationTarget(rep); got != "m!/native/boot.dll" {
		t.Fatalf("结构命中应取 boot 路径，got %q", got)
	}
}

// 无结构命中（clean/低分）但有原生 PE：兜底挑原生 PE，优先 native/ 目录、.dll 优先。
func TestDetonationTargetFallback(t *testing.T) {
	rep := &scan.Report{
		Files: []scan.FileInfo{
			{Path: "m!/plugin/mgr.dll", Kind: "pe-dotnet"},   // 托管，跳过
			{Path: "m!/plugin/bin/tool.exe", Kind: "pe-native"},
			{Path: "m!/native/hidden.dll", Kind: "pe-native"}, // native/ + .dll，最高分
		},
	}
	if got := DetonationTarget(rep); got != "m!/native/hidden.dll" {
		t.Fatalf("兜底应优先 native/ 下的 .dll，got %q", got)
	}
}

// 纯资源包 / 仅托管：无原生 PE，返回空 → 调用方跳过排队。
func TestDetonationTargetNone(t *testing.T) {
	rep := &scan.Report{
		Files: []scan.FileInfo{
			{Path: "m!/plugin/only-managed.dll", Kind: "pe-dotnet"},
		},
	}
	if got := DetonationTarget(rep); got != "" {
		t.Fatalf("无原生 PE 应返回空，got %q", got)
	}
}
