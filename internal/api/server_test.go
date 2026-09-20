package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpetmod-scanner/internal/scan"
	"vpetmod-scanner/internal/store"
)

func newTestServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	cfg.Limits = scan.DefaultLimits()
	if cfg.MaxUpload == 0 {
		cfg.MaxUpload = 64 << 20
	}
	cfg.DataDir = t.TempDir()
	cfg.Workers = 2
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })
	return ts
}

type submitResp struct {
	Task  store.Task `json:"task"`
	Dedup bool       `json:"dedup"`
}

func TestUploadZipAsyncMalicious(t *testing.T) {
	data, err := os.ReadFile("../../../Test/depot_1920960_4637760495230589419.zip")
	if err != nil {
		t.Skip("样本不存在")
	}
	ts := newTestServer(t, Config{})

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "../../evil/name.zip")
	fw.Write(data)
	mw.Close()

	// wait=60 让服务端同步等到扫描完成再返回。
	resp, err := http.Post(ts.URL+"/api/v1/scan?wait=60", mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	var sr submitResp
	json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()
	if sr.Task.State != store.Done {
		t.Fatalf("state=%s", sr.Task.State)
	}
	if sr.Task.Report == nil || sr.Task.Report.Verdict != scan.Malicious {
		t.Fatalf("verdict=%v", sr.Task.Report)
	}
	if strings.Contains(sr.Task.Filename, "..") || strings.Contains(sr.Task.Filename, "/") {
		t.Fatalf("文件名未清洗: %s", sr.Task.Filename)
	}

	// 再传一次相同内容 → dedup 命中，不重新扫描。
	var body2 bytes.Buffer
	mw2 := multipart.NewWriter(&body2)
	fw2, _ := mw2.CreateFormFile("file", "again.zip")
	fw2.Write(data)
	mw2.Close()
	resp2, _ := http.Post(ts.URL+"/api/v1/scan", mw2.FormDataContentType(), &body2)
	var sr2 submitResp
	json.NewDecoder(resp2.Body).Decode(&sr2)
	resp2.Body.Close()
	if !sr2.Dedup || sr2.Task.ID != sr.Task.ID {
		t.Fatalf("dedup=%v id=%s want %s", sr2.Dedup, sr2.Task.ID, sr.Task.ID)
	}
}

func TestReviewFlow(t *testing.T) {
	ts := newTestServer(t, Config{})
	resp, _ := http.Post(ts.URL+"/api/v1/scan?wait=30&name=a.txt", "application/octet-stream", strings.NewReader("hello world"))
	var sr submitResp
	json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()
	id := sr.Task.ID

	body, _ := json.Marshal(map[string]string{"decision": "approved", "reviewer": "alice", "note": "看过了"})
	resp, _ = http.Post(ts.URL+"/api/v1/tasks/"+id+"/review", "application/json", bytes.NewReader(body))
	var reviewed store.Task
	json.NewDecoder(resp.Body).Decode(&reviewed)
	resp.Body.Close()
	if reviewed.Review != store.Approved || reviewed.Reviewer != "alice" {
		t.Fatalf("review=%+v", reviewed)
	}

	// 审核日志应记录 submit / scan_done / approve。
	resp, _ = http.Get(ts.URL + "/api/v1/audit")
	var au struct {
		Audit []store.AuditEntry `json:"audit"`
	}
	json.NewDecoder(resp.Body).Decode(&au)
	resp.Body.Close()
	acts := map[string]bool{}
	for _, e := range au.Audit {
		acts[e.Action] = true
	}
	for _, want := range []string{"submit", "scan_done", "approve"} {
		if !acts[want] {
			t.Errorf("审核日志缺少 %s", want)
		}
	}

	// 列表过滤 review=approved 应能查到它。
	resp, _ = http.Get(ts.URL + "/api/v1/tasks?review=approved")
	var lst struct {
		Tasks []store.Task `json:"tasks"`
		Total int          `json:"total"`
	}
	json.NewDecoder(resp.Body).Decode(&lst)
	resp.Body.Close()
	if lst.Total != 1 || lst.Tasks[0].ID != id {
		t.Fatalf("list=%+v", lst)
	}
}

func TestReviewBadDecision(t *testing.T) {
	ts := newTestServer(t, Config{})
	resp, _ := http.Post(ts.URL+"/api/v1/scan?wait=30&name=a.txt", "application/octet-stream", strings.NewReader("x"))
	var sr submitResp
	json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()
	body, _ := json.Marshal(map[string]string{"decision": "maybe", "reviewer": "bob"})
	resp, _ = http.Post(ts.URL+"/api/v1/tasks/"+sr.Task.ID+"/review", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Limits: scan.DefaultLimits(), MaxUpload: 1 << 20, DataDir: dir, Workers: 1}

	s1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts1 := httptest.NewServer(s1.Handler())
	resp, _ := http.Post(ts1.URL+"/api/v1/scan?wait=30&name=a.txt", "application/octet-stream", strings.NewReader("hi"))
	var sr submitResp
	json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()
	ts1.Close()
	s1.Close()

	// 新实例从磁盘恢复任务。
	s2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	ts2 := httptest.NewServer(s2.Handler())
	defer ts2.Close()
	resp, _ = http.Get(ts2.URL + "/api/v1/tasks/" + sr.Task.ID)
	var got store.Task
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.ID != sr.Task.ID || got.State != store.Done {
		t.Fatalf("restored=%+v", got)
	}
}

func TestUploadTooLarge(t *testing.T) {
	ts := newTestServer(t, Config{MaxUpload: 1024})
	resp, err := http.Post(ts.URL+"/api/v1/scan", "application/octet-stream", bytes.NewReader(make([]byte, 4096)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPathScanDisabledByDefault(t *testing.T) {
	ts := newTestServer(t, Config{})
	resp, _ := http.Post(ts.URL+"/api/v1/scan/path", "application/json", strings.NewReader(`{"path":"C:\\"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestPathScanConfinedToRoot(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "mod"), 0o755)
	os.WriteFile(filepath.Join(root, "mod", "info.lps"), []byte("vupmod#ok:|"), 0o644)
	ts := newTestServer(t, Config{AllowRoots: []string{root}})

	post := func(p string) int {
		b, _ := json.Marshal(map[string]string{"path": p})
		resp, err := http.Post(ts.URL+"/api/v1/scan/path", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(filepath.Join(root, "mod")); c != 200 {
		t.Fatalf("root 内路径 status=%d", c)
	}
	if c := post(filepath.Join(root, "..")); c != http.StatusForbidden {
		t.Fatalf("root 外路径 status=%d", c)
	}
	if c := post(root + "_sibling"); c != http.StatusForbidden {
		t.Fatalf("同前缀兄弟目录 status=%d", c)
	}
}

func TestTokenAuth(t *testing.T) {
	ts := newTestServer(t, Config{Token: "s3cret"})
	resp, _ := http.Get(ts.URL + "/api/v1/rules")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("无 token status=%d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("有 token status=%d", resp.StatusCode)
	}
	// healthz 与首页不鉴权。
	for _, p := range []string{"/healthz", "/"} {
		resp, _ = http.Get(ts.URL + p)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s status=%d", p, resp.StatusCode)
		}
	}
}

func TestDynamicAttach(t *testing.T) {
	ts := newTestServer(t, Config{})
	resp, _ := http.Post(ts.URL+"/api/v1/scan?wait=30&name=a.zip", "application/octet-stream", strings.NewReader("hello"))
	var sr submitResp
	json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()
	id := sr.Task.ID

	dr := map[string]any{
		"source": "linux-wine", "verdict": "malicious",
		"endpoints": []map[string]string{{"target": "c2.evil.top:443", "proto": "tls", "source": "sinkhole"}},
		"requests":  []map[string]any{{"proto": "http", "host": "c2.evil.top", "dport": 80, "request": "POST /gate", "bytes": 40, "hex": "00 01"}},
		"canary_exfil": []string{"token=CANARY-X canary=steam-ssfn"},
	}
	body, _ := json.Marshal(dr)
	resp, _ = http.Post(ts.URL+"/api/v1/tasks/"+id+"/dynamic", "application/json", bytes.NewReader(body))
	var got store.Task
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if resp.StatusCode != 200 || got.Dynamic == nil {
		t.Fatalf("status=%d dynamic=%v", resp.StatusCode, got.Dynamic)
	}
	if len(got.Dynamic.Endpoints) != 1 || got.Dynamic.Endpoints[0].Target != "c2.evil.top:443" {
		t.Fatalf("endpoints=%+v", got.Dynamic.Endpoints)
	}
	// 详情 GET 应带回 dynamic；列表应只给 has_dynamic 摘要
	resp, _ = http.Get(ts.URL + "/api/v1/tasks/" + id)
	var full store.Task
	json.NewDecoder(resp.Body).Decode(&full)
	resp.Body.Close()
	if full.Dynamic == nil || len(full.Dynamic.Requests) != 1 {
		t.Fatalf("detail dynamic=%v", full.Dynamic)
	}
	resp, _ = http.Get(ts.URL + "/api/v1/tasks")
	var lst struct{ Tasks []store.Task `json:"tasks"` }
	json.NewDecoder(resp.Body).Decode(&lst)
	resp.Body.Close()
	if len(lst.Tasks) != 1 || !lst.Tasks[0].HasDynamic || lst.Tasks[0].Dynamic != nil {
		t.Fatalf("list has_dynamic=%v dynamic=%v", lst.Tasks[0].HasDynamic, lst.Tasks[0].Dynamic)
	}
}

func TestAutoDynamicQueue(t *testing.T) {
	data, err := os.ReadFile("../../../Test/depot_1920960_4637760495230589419.zip")
	if err != nil {
		t.Skip("样本不存在")
	}
	ts := newTestServer(t, Config{AutoDynamic: true, DynamicTriggers: []string{"malicious", "suspicious"}})

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "s.zip")
	fw.Write(data)
	mw.Close()
	resp, _ := http.Post(ts.URL+"/api/v1/scan?wait=60", mw.FormDataContentType(), &body)
	var sr submitResp
	json.NewDecoder(resp.Body).Decode(&sr)
	resp.Body.Close()
	if sr.Task.Report == nil || sr.Task.Report.Verdict != scan.Malicious {
		t.Fatalf("verdict=%v", sr.Task.Report)
	}

	// 恶意样本应被自动排入动态队列，worker 能认领到并拿到 boot target。
	resp, _ = http.Get(ts.URL + "/api/v1/dynamic/next")
	if resp.StatusCode != 200 {
		t.Fatalf("claim status=%d", resp.StatusCode)
	}
	var job struct {
		TaskID string `json:"task_id"`
		Target string `json:"target"`
	}
	json.NewDecoder(resp.Body).Decode(&job)
	resp.Body.Close()
	if job.TaskID != sr.Task.ID || job.Target == "" {
		t.Fatalf("job=%+v", job)
	}
	if !strings.Contains(job.Target, "native/") {
		t.Fatalf("target 不像 boot dll: %s", job.Target)
	}

	// worker 能下载原始样本。
	resp, _ = http.Get(ts.URL + "/api/v1/tasks/" + job.TaskID + "/file")
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(got) != len(data) {
		t.Fatalf("下载大小不符 %d != %d", len(got), len(data))
	}

	// 认领后不应再被重复认领。
	resp, _ = http.Get(ts.URL + "/api/v1/dynamic/next")
	sc := resp.StatusCode
	resp.Body.Close()
	if sc != http.StatusNoContent {
		t.Fatalf("重复认领 status=%d", sc)
	}
}
