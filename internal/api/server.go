// Package api 把扫描器封装成 HTTP 服务：异步提交、任务查询、人工审核、审核日志，附一个审核页面。
package api

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpetmod-scanner/internal/scan"
	"vpetmod-scanner/internal/store"
	"vpetmod-scanner/internal/worker"
)

//go:embed web/index.html
var webFS embed.FS

type Config struct {
	Listen    string
	Token     string // 为空则不鉴权（仅建议在 127.0.0.1 上这样用）
	MaxUpload int64
	DataDir   string
	Workers   int
	QueueSize int
	// AutoDynamic 开启后，静态命中 DynamicTriggers 里的结论即自动排动态分析（由外部 worker 认领执行）。
	AutoDynamic     bool
	DynamicTriggers []string
	// AllowRoots 非空才开放 /api/v1/scan/path，且只允许扫描这些目录之内的路径。
	AllowRoots []string
	Limits     scan.Limits
	Version    string
}

type Server struct {
	cfg      Config
	roots    []string
	store    *store.Store
	pool     *worker.Pool
	autoDyn  bool
	triggers map[string]bool
}

// maybeEnqueueDynamic：对已完成、达触发线、尚无动态结果的任务补排动态分析（去重命中时用）。
func (s *Server) maybeEnqueueDynamic(t *store.Task) {
	if !s.autoDyn || t == nil || t.Report == nil || t.DynamicState != "" || t.Dynamic != nil {
		return
	}
	if s.triggers[string(t.Report.Verdict)] {
		if target := worker.DetonationTarget(t.Report); target != "" {
			s.store.EnqueueDynamic(t.ID, target)
		}
	}
}

func New(cfg Config) (*Server, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: st}
	s.pool = worker.New(st, cfg.Limits, cfg.Workers, cfg.QueueSize)
	if cfg.AutoDynamic {
		triggers := cfg.DynamicTriggers
		if len(triggers) == 0 {
			triggers = []string{"malicious", "suspicious"}
		}
		s.pool.SetAutoDynamic(true, triggers)
		s.autoDyn = true
		s.triggers = map[string]bool{}
		for _, v := range triggers {
			s.triggers[v] = true
		}
	}
	s.pool.Start()
	for _, r := range cfg.AllowRoots {
		abs, err := filepath.Abs(r)
		if err != nil {
			return nil, err
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			abs = real
		}
		s.roots = append(s.roots, filepath.Clean(abs))
	}
	return s, nil
}

func (s *Server) Close() error {
	s.pool.Stop()
	return s.store.Close()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.cfg.Version})
	})
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /api/v1/rules", s.auth(s.handleRules))
	mux.HandleFunc("POST /api/v1/scan", s.auth(s.handleSubmit))
	mux.HandleFunc("POST /api/v1/scan/path", s.auth(s.handlePath))
	mux.HandleFunc("GET /api/v1/tasks", s.auth(s.handleList))
	mux.HandleFunc("DELETE /api/v1/tasks", s.auth(s.handleDeleteAll))
	mux.HandleFunc("GET /api/v1/tasks/{id}", s.auth(s.handleGet))
	mux.HandleFunc("DELETE /api/v1/tasks/{id}", s.auth(s.handleDelete))
	mux.HandleFunc("POST /api/v1/tasks/{id}/rescan", s.auth(s.handleRescan))
	mux.HandleFunc("POST /api/v1/tasks/{id}/review", s.auth(s.handleReview))
	mux.HandleFunc("POST /api/v1/tasks/{id}/dynamic", s.auth(s.handleDynamic))
	mux.HandleFunc("POST /api/v1/tasks/{id}/dynamic-error", s.auth(s.handleDynamicError))
	mux.HandleFunc("POST /api/v1/dynamic", s.auth(s.handleDynamicBySHA))
	mux.HandleFunc("GET /api/v1/dynamic/next", s.auth(s.handleDynamicNext))
	mux.HandleFunc("GET /api/v1/tasks/{id}/file", s.auth(s.handleFile))
	mux.HandleFunc("GET /api/v1/audit", s.auth(s.handleAudit))
	return mux
}

func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
	}
	log.Printf("vpetmod-scanner %s listening on %s (data=%s workers=%d path-scan=%v)",
		s.cfg.Version, s.cfg.Listen, s.cfg.DataDir, s.cfg.Workers, len(s.roots) > 0)
	return srv.ListenAndServe()
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	if s.cfg.Token == "" {
		return h
	}
	want := []byte("Bearer " + s.cfg.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if got == "" {
			got = "Bearer " + r.URL.Query().Get("token") // 便于页面用 EventSource/下载场景
		}
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": scan.Rules, "iocs": scan.IOCs()})
}

// handleSubmit 接收上传，创建异步扫描任务。
// multipart 字段 "file"，或直接把文件作为请求体（?name= 指定文件名）。
// 查询参数：submitter=、force=1 跳过去重、wait=<秒> 同步等待结果（上限 120s）。
func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload)

	var src io.Reader
	name := r.URL.Query().Get("name")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				writeErr(w, http.StatusBadRequest, "multipart 中缺少 file 字段")
				return
			}
			if part.FormName() == "file" {
				if name == "" {
					name = part.FileName()
				}
				src = part
				break
			}
			part.Close()
		}
	} else {
		src = r.Body
	}
	if name == "" {
		name = "upload"
	}
	name = filepath.Base(filepath.Clean("/" + strings.ReplaceAll(name, "\\", "/")))

	data, err := io.ReadAll(src)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "上传超过大小上限")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(data) == 0 {
		writeErr(w, http.StatusBadRequest, "空文件")
		return
	}

	force := r.URL.Query().Get("force") == "1"
	t, dedup, err := s.store.Submit(name, r.URL.Query().Get("submitter"), data, force)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if dedup {
		log.Printf("submit %q sha=%s -> dedup task %s", name, t.SHA256[:12], t.ID)
		// 去重命中的旧任务若从没做过动态分析且结论达触发线，也补排一次（例如它是在自动动态上线前扫的）。
		s.maybeEnqueueDynamic(t)
		if t2, err := s.store.Get(t.ID); err == nil {
			t = t2
		}
		writeJSON(w, http.StatusOK, map[string]any{"task": t, "dedup": true})
		return
	}
	if !s.pool.Enqueue(t.ID) {
		writeErr(w, http.StatusServiceUnavailable, "扫描队列已满，请稍后重试")
		return
	}
	log.Printf("submit %q sha=%s -> task %s queued", name, t.SHA256[:12], t.ID)

	if sec := waitSeconds(r.URL.Query().Get("wait")); sec > 0 {
		if done := s.waitFor(r.Context(), t.ID, time.Duration(sec)*time.Second); done != nil {
			writeJSON(w, http.StatusOK, map[string]any{"task": done, "dedup": false})
			return
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"task": t, "dedup": false})
}

func (s *Server) waitFor(ctx context.Context, id string, d time.Duration) *store.Task {
	deadline := time.After(d)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline:
			return nil
		case <-tick.C:
			if t, err := s.store.Get(id); err == nil && (t.State == store.Done || t.State == store.Errored) {
				return t
			}
		}
	}
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ListFilter{
		State:   store.State(q.Get("state")),
		Review:  store.Review(q.Get("review")),
		Verdict: q.Get("verdict"),
		Limit:   atoiDefault(q.Get("limit"), 50),
		Offset:  atoiDefault(q.Get("offset"), 0),
	}
	items, total := s.store.List(f)
	writeJSON(w, http.StatusOK, map[string]any{"tasks": items, "total": total, "limit": f.Limit, "offset": f.Offset})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.Get(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Decision string `json:"decision"`
		Reviewer string `json:"reviewer"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体应为 JSON")
		return
	}
	t, err := s.store.SetReview(r.PathValue("id"), store.Review(req.Decision), req.Reviewer, req.Note)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "任务不存在")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("review task %s -> %s by %q", t.ID, t.Review, t.Reviewer)
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Delete(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "任务不存在")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("delete task %s", id)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleDeleteAll(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.DeleteAll()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("delete all tasks: %d cleared", n)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// handleRescan 用已存的原始样本按当前规则重新扫描（清掉旧结论/动态/审核后重入队列）。
func (s *Server) handleRescan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := s.store.ResetForRescan(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "任务不存在")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.pool.Enqueue(id) {
		writeErr(w, http.StatusServiceUnavailable, "扫描队列已满，请稍后重试")
		return
	}
	log.Printf("rescan task %s queued", id)
	if sec := waitSeconds(r.URL.Query().Get("wait")); sec > 0 {
		if done := s.waitFor(r.Context(), id, time.Duration(sec)*time.Second); done != nil {
			writeJSON(w, http.StatusOK, map[string]any{"task": done})
			return
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"task": t})
}

// handleDynamic 接收隔离环境回传的动态分析结果（外联地址/请求包等），挂到指定任务上。
func (s *Server) handleDynamic(w http.ResponseWriter, r *http.Request) {
	dr, err := decodeDynamic(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	t, err := s.store.SetDynamic(r.PathValue("id"), dr)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "任务不存在")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("dynamic attached task %s: endpoints=%d requests=%d exfil=%d", t.ID, len(dr.Endpoints), len(dr.Requests), len(dr.CanaryExfil))
	writeJSON(w, http.StatusOK, t)
}

// handleDynamicBySHA 按 SHA256 找任务再挂动态结果，便于隔离环境不知道 task id 时回传。
func (s *Server) handleDynamicBySHA(w http.ResponseWriter, r *http.Request) {
	sha := r.URL.Query().Get("sha256")
	if sha == "" {
		writeErr(w, http.StatusBadRequest, "缺少 ?sha256=")
		return
	}
	id := s.store.FindBySHA(sha)
	if id == "" {
		writeErr(w, http.StatusNotFound, "没有该 SHA256 对应的任务")
		return
	}
	dr, err := decodeDynamic(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	t, err := s.store.SetDynamic(id, dr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("dynamic attached task %s (by sha): endpoints=%d requests=%d", t.ID, len(dr.Endpoints), len(dr.Requests))
	writeJSON(w, http.StatusOK, t)
}

// handleDynamicNext 供动态 worker 轮询：认领一个待引爆任务并置 running；无则 204。
func (s *Server) handleDynamicNext(w http.ResponseWriter, r *http.Request) {
	t := s.store.ClaimDynamic()
	if t == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task_id": t.ID, "sha256": t.SHA256, "filename": t.Filename, "target": t.DynamicTarget,
	})
}

// handleFile 供 worker 下载待引爆的原始样本。
func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.Get(id); err != nil {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	f, err := os.Open(s.store.UploadPath(id))
	if err != nil {
		writeErr(w, http.StatusNotFound, "原文件不存在")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

// handleDynamicError 供 worker 回报动态引爆失败。
func (s *Server) handleDynamicError(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
	s.store.SetDynamicError(r.PathValue("id"), req.Error)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
}

func decodeDynamic(r *http.Request) (*store.DynamicReport, error) {
	var dr store.DynamicReport
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&dr); err != nil {
		return nil, errors.New("请求体应为动态报告 JSON")
	}
	return &dr, nil
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.Audits(atoiDefault(r.URL.Query().Get("limit"), 200))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}

func (s *Server) handlePath(w http.ResponseWriter, r *http.Request) {
	if len(s.roots) == 0 {
		writeErr(w, http.StatusForbidden, "服务端路径扫描未启用（启动时用 -allow-root 指定允许的目录）")
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil || req.Path == "" {
		writeErr(w, http.StatusBadRequest, `请求体应为 {"path": "..."}`)
		return
	}
	p, ok := s.within(req.Path)
	if !ok {
		writeErr(w, http.StatusForbidden, "路径不在允许的目录内")
		return
	}
	rep, err := scan.ScanPath(p, s.cfg.Limits)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	log.Printf("scan path %q: %s score=%d", p, rep.Verdict, rep.Score)
	writeJSON(w, http.StatusOK, rep)
}

// within 先解析符号链接再比较前缀，防止用联接点跳出白名单目录。
func (s *Server) within(p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	real = filepath.Clean(real)
	for _, root := range s.roots {
		rel, err := filepath.Rel(root, real)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return real, true
		}
	}
	return "", false
}

func waitSeconds(s string) int {
	n := atoiDefault(s, 0)
	if n < 0 {
		return 0
	}
	if n > 120 {
		return 120
	}
	return n
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
