package scan

import "sort"

type Verdict string

const (
	Clean      Verdict = "clean"
	Suspicious Verdict = "suspicious"
	Malicious  Verdict = "malicious"
)

// 分值阈值：critical=100 单条即恶意；两条 high 叠加也判恶意。
const (
	maliciousScore  = 80
	suspiciousScore = 30
)

func verdictOf(score int, findings []Finding) Verdict {
	for _, f := range findings {
		if f.Severity == Critical {
			return Malicious
		}
	}
	switch {
	case score >= maliciousScore:
		return Malicious
	case score >= suspiciousScore:
		return Suspicious
	}
	return Clean
}

type Finding struct {
	Rule     string            `json:"rule"`
	Severity Severity          `json:"severity"`
	Title    string            `json:"title"`
	Path     string            `json:"path"`
	Detail   string            `json:"detail,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

func newFinding(ruleID, path, detail string, ev map[string]string) Finding {
	r := ruleIndex[ruleID]
	return Finding{Rule: r.ID, Severity: r.Severity, Title: r.Title, Path: path, Detail: detail, Evidence: ev}
}

type FileInfo struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"` // pe-native / pe-dotnet
}

type ModReport struct {
	Root     string    `json:"root"`
	Name     string    `json:"name,omitempty"`
	Author   string    `json:"author,omitempty"`
	Verdict  Verdict   `json:"verdict"`
	Score    int       `json:"score"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Target   string      `json:"target"`
	Verdict  Verdict     `json:"verdict"`
	Score    int         `json:"score"`
	Mods     []ModReport `json:"mods"`
	Loose    []Finding   `json:"loose_findings,omitempty"` // 不属于任何 MOD 目录的发现
	Files    []FileInfo  `json:"pe_files"`
	Scanned  int         `json:"scanned_files"`
	Warnings []string    `json:"warnings,omitempty"`
	// NetworkIndicators 是静态提取到的外联地址/内嵌密钥（主要来自托管插件的明文字符串）。
	NetworkIndicators []NetIndicator `json:"network_indicators,omitempty"`
}

type NetIndicator struct {
	Kind  string `json:"kind"` // url / ip / secret
	Value string `json:"value"`
	Path  string `json:"path"`
}

// score 按规则去重计分：同一规则在一个 MOD 里命中多次只算一次，
// 否则一个 MOD 里放 20 个无害脚本就能把分数堆到"恶意"。
func score(fs []Finding) int {
	seen := map[string]bool{}
	s := 0
	for _, f := range fs {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			s += f.Severity.Score()
		}
	}
	return s
}

func sortFindings(fs []Finding) {
	rank := map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3}
	sort.SliceStable(fs, func(i, j int) bool {
		if rank[fs[i].Severity] != rank[fs[j].Severity] {
			return rank[fs[i].Severity] < rank[fs[j].Severity]
		}
		return fs[i].Path < fs[j].Path
	})
}
