// Package store 持久化扫描任务与审核记录。
// 每个任务一个 JSON 文件（原子写），审核动作追加到 audit.jsonl。纯标准库。
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"vpetmod-scanner/internal/scan"
)

type State string

const (
	Queued  State = "queued"
	Running State = "running"
	Done    State = "done"
	Errored State = "error"
)

type Review string

const (
	Pending  Review = "pending"
	Approved Review = "approved"
	Rejected Review = "rejected"
)

type Task struct {
	ID        string       `json:"id"`
	Filename  string       `json:"filename"`
	SHA256    string       `json:"sha256"`
	Size      int64        `json:"size"`
	State     State        `json:"state"`
	Submitter string       `json:"submitter,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	StartedAt *time.Time   `json:"started_at,omitempty"`
	EndedAt   *time.Time   `json:"ended_at,omitempty"`
	Report    *scan.Report `json:"report,omitempty"`
	Error     string       `json:"error,omitempty"`

	// Verdict/Score 是列表页用的结论摘要；List 会剥掉 Report 只保留这两项。
	Verdict string `json:"verdict,omitempty"`
	Score   int    `json:"score,omitempty"`

	// 审核状态：扫描结论是机器判定，Review 是人工裁决，二者独立。
	Review     Review     `json:"review"`
	Reviewer   string     `json:"reviewer,omitempty"`
	ReviewNote string     `json:"review_note,omitempty"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`

	// 动态分析结果（外联地址/请求包等），由隔离环境的引爆工具回传；静态扫描不产出这些。
	Dynamic    *DynamicReport `json:"dynamic,omitempty"`
	HasDynamic bool           `json:"has_dynamic,omitempty"` // 列表页用：是否已有动态分析

	// 动态分析自动流水线状态： ""(未触发) / pending(待引爆) / running(引爆中) / done / error
	DynamicState  string `json:"dynamic_state,omitempty"`
	DynamicTarget string `json:"dynamic_target,omitempty"` // 待引爆的 boot dll 在包内展示路径（静态扫描定位）
	DynamicError  string `json:"dynamic_error,omitempty"`
}

// DynamicReport 是隔离环境动态引爆的结果，回传后在审核网页展示。
type DynamicReport struct {
	Source           string      `json:"source,omitempty"` // linux-wine / windows-vm / manual
	Verdict          string      `json:"verdict,omitempty"`
	SubmittedAt      time.Time   `json:"submitted_at"`
	Endpoints        []Endpoint  `json:"endpoints,omitempty"`
	Requests         []ReqPacket `json:"requests,omitempty"`
	CredentialAccess []string    `json:"credential_access,omitempty"`
	CanariesPlanted  []string    `json:"canaries_planted,omitempty"` // 种了哪些金丝雀诱饵（取证：负结果也留痕）
	CanaryCount      int         `json:"canary_count,omitempty"`
	ExfilChecked     bool        `json:"exfil_checked,omitempty"` // 是否真做了外发监控（区分"没查"与"查了没发现"）
	CanaryExfil      []string    `json:"canary_exfil,omitempty"`
	DroppedPE        []string    `json:"dropped_pe,omitempty"`
	SteamUITamper    []string    `json:"steamui_tamper,omitempty"`
	Note             string      `json:"note,omitempty"`
}

type Endpoint struct {
	Target string `json:"target"` // IP/域名:端口
	Proto  string `json:"proto,omitempty"`
	Source string `json:"source,omitempty"` // strace / sinkhole / procmon
	Result string `json:"result,omitempty"`
}

type ReqPacket struct {
	Proto   string `json:"proto,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Dport   int    `json:"dport,omitempty"`
	Host    string `json:"host,omitempty"`
	SNI     string `json:"sni,omitempty"`
	Request string `json:"request,omitempty"`
	Bytes   int    `json:"bytes,omitempty"`
	Hex     string `json:"hex,omitempty"`
}

func (t *Task) clone() *Task {
	c := *t
	return &c
}

type AuditEntry struct {
	Time     time.Time `json:"time"`
	TaskID   string    `json:"task_id"`
	SHA256   string    `json:"sha256"`
	Action   string    `json:"action"` // submit / scan_done / scan_error / approve / reject
	Actor    string    `json:"actor,omitempty"`
	Verdict  string    `json:"verdict,omitempty"`
	Note     string    `json:"note,omitempty"`
	Filename string    `json:"filename,omitempty"`
}

type Store struct {
	dir     string
	uploads string
	mu      sync.RWMutex
	tasks   map[string]*Task
	bySHA   map[string]string // sha256 → 最近一个任务 ID
	auditW  *os.File
	auditMu sync.Mutex
	seq     uint64
}

func Open(dir string) (*Store, error) {
	uploads := filepath.Join(dir, "uploads")
	for _, d := range []string{dir, uploads, filepath.Join(dir, "tasks")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	s := &Store{dir: dir, uploads: uploads, tasks: map[string]*Task{}, bySHA: map[string]string{}}
	if err := s.loadTasks(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	s.auditW = f
	return s, nil
}

func (s *Store) Close() error {
	if s.auditW != nil {
		return s.auditW.Close()
	}
	return nil
}

func (s *Store) loadTasks() error {
	entries, err := os.ReadDir(filepath.Join(s.dir, "tasks"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, "tasks", e.Name()))
		if err != nil {
			continue
		}
		var t Task
		if json.Unmarshal(b, &t) != nil || t.ID == "" {
			continue
		}
		// 崩溃残留：加载时仍处于 queued/running 的任务标记为 error，避免"永远卡住"。
		if t.State == Queued || t.State == Running {
			t.State = Errored
			t.Error = "服务重启，任务中断，请重新提交"
		}
		// 动态引爆中途重启：worker 可能已死，退回 pending 让其他 worker 重新认领。
		if t.DynamicState == "running" {
			t.DynamicState = "pending"
		}
		s.tasks[t.ID] = &t
		if t.SHA256 != "" {
			s.bySHA[t.SHA256] = t.ID
		}
	}
	return nil
}

// UploadPath 返回某任务上传原文件的落盘路径（供 worker 扫描、审核复查）。
func (s *Store) UploadPath(id string) string { return filepath.Join(s.uploads, id+".bin") }

var ErrNotFound = errors.New("task not found")

// Submit 落盘上传内容，创建一个 queued 任务。若同 SHA256 已有 done 任务且 !force，直接返回它（dedup=true）。
func (s *Store) Submit(filename, submitter string, data []byte, force bool) (t *Task, dedup bool, err error) {
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	s.mu.Lock()
	if !force {
		if id, ok := s.bySHA[sha]; ok {
			if prev, ok := s.tasks[id]; ok && prev.State == Done {
				c := prev.clone()
				s.mu.Unlock()
				return c, true, nil
			}
		}
	}
	id := s.newID()
	now := time.Now().UTC()
	t = &Task{ID: id, Filename: filename, SHA256: sha, Size: int64(len(data)),
		State: Queued, Submitter: submitter, CreatedAt: now, Review: Pending}
	s.tasks[id] = t
	s.bySHA[sha] = id
	s.mu.Unlock()

	if err := os.WriteFile(s.UploadPath(id), data, 0o644); err != nil {
		s.mu.Lock()
		t.State = Errored
		t.Error = "落盘失败: " + err.Error()
		s.mu.Unlock()
		_ = s.persist(t)
		return t.clone(), false, err
	}
	if err := s.persist(t); err != nil {
		return t.clone(), false, err
	}
	s.Audit(AuditEntry{TaskID: id, SHA256: sha, Action: "submit", Actor: submitter, Filename: filename})
	return t.clone(), false, nil
}

// MarkRunning 供 worker 领取任务时调用。
func (s *Store) MarkRunning(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.tasks[id]; t != nil {
		t.State = Running
		now := time.Now().UTC()
		t.StartedAt = &now
		_ = s.persist(t)
	}
}

// Finish 写回扫描结果（rep 非空为成功，err 非空为失败）。
func (s *Store) Finish(id string, rep *scan.Report, scanErr error) {
	s.mu.Lock()
	t := s.tasks[id]
	if t == nil {
		s.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	t.EndedAt = &now
	var ae AuditEntry
	if scanErr != nil {
		t.State = Errored
		t.Error = scanErr.Error()
		ae = AuditEntry{TaskID: id, SHA256: t.SHA256, Action: "scan_error", Note: scanErr.Error()}
	} else {
		t.State = Done
		t.Report = rep
		ae = AuditEntry{TaskID: id, SHA256: t.SHA256, Action: "scan_done", Verdict: string(rep.Verdict)}
	}
	_ = s.persist(t)
	s.mu.Unlock()
	s.Audit(ae)
}

// SetReview 记录人工裁决，写入审核日志。
func (s *Store) SetReview(id string, decision Review, reviewer, note string) (*Task, error) {
	if decision != Approved && decision != Rejected {
		return nil, fmt.Errorf("非法审核结论: %s", decision)
	}
	s.mu.Lock()
	t := s.tasks[id]
	if t == nil {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	t.Review = decision
	t.Reviewer = reviewer
	t.ReviewNote = note
	t.ReviewedAt = &now
	_ = s.persist(t)
	c := t.clone()
	s.mu.Unlock()

	action := "approve"
	if decision == Rejected {
		action = "reject"
	}
	s.Audit(AuditEntry{TaskID: id, SHA256: c.SHA256, Action: action, Actor: reviewer, Note: note, Filename: c.Filename})
	return c, nil
}

// SetDynamic 写入/覆盖某任务的动态分析结果（由隔离环境引爆工具回传）。
func (s *Store) SetDynamic(id string, dr *DynamicReport) (*Task, error) {
	if dr == nil {
		return nil, fmt.Errorf("空的动态报告")
	}
	if dr.SubmittedAt.IsZero() {
		dr.SubmittedAt = time.Now().UTC()
	}
	s.mu.Lock()
	t := s.tasks[id]
	if t == nil {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	t.Dynamic = dr
	t.DynamicState = "done"
	t.DynamicError = ""
	_ = s.persist(t)
	c := t.clone()
	s.mu.Unlock()
	s.Audit(AuditEntry{TaskID: id, SHA256: c.SHA256, Action: "dynamic",
		Actor: dr.Source, Verdict: dr.Verdict,
		Note: fmt.Sprintf("外联 %d 个/请求 %d 个/凭证外发 %d 项", len(dr.Endpoints), len(dr.Requests), len(dr.CanaryExfil))})
	return c, nil
}

// EnqueueDynamic 把任务标记为待动态引爆（静态判恶意/可疑后由 worker 自动认领）。
func (s *Store) EnqueueDynamic(id, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.tasks[id]; t != nil && t.DynamicState == "" {
		t.DynamicState = "pending"
		t.DynamicTarget = target
		_ = s.persist(t)
	}
}

// ClaimDynamic 领取一个 pending 的动态任务并置 running（供 worker 轮询）。无则返回 nil。
func (s *Store) ClaimDynamic() *Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pick *Task
	for _, t := range s.tasks {
		if t.DynamicState == "pending" && (pick == nil || t.CreatedAt.Before(pick.CreatedAt)) {
			pick = t
		}
	}
	if pick == nil {
		return nil
	}
	pick.DynamicState = "running"
	_ = s.persist(pick)
	return pick.clone()
}

// SetDynamicError 把动态任务标记为失败（worker 引爆/分析出错时回报）。
func (s *Store) SetDynamicError(id, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t := s.tasks[id]; t != nil {
		t.DynamicState = "error"
		t.DynamicError = msg
		_ = s.persist(t)
	}
}

// FindBySHA 返回某 SHA256 对应的最近任务 ID（找不到返回空）。
func (s *Store) FindBySHA(sha string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bySHA[sha]
}

func (s *Store) Get(id string) (*Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t := s.tasks[id]; t != nil {
		return t.clone(), nil
	}
	return nil, ErrNotFound
}

type ListFilter struct {
	State   State
	Review  Review
	Verdict string
	Limit   int
	Offset  int
}

// List 按创建时间倒序返回任务（不含 Report 大对象，用于列表页）。
// 全程持读锁并在锁内克隆，避免与 worker 的写入竞争。
func (s *Store) List(f ListFilter) (items []*Task, total int) {
	s.mu.RLock()
	all := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		if f.State != "" && t.State != f.State {
			continue
		}
		if f.Review != "" && t.Review != f.Review {
			continue
		}
		verdict := ""
		if t.Report != nil {
			verdict = string(t.Report.Verdict)
		}
		if f.Verdict != "" && verdict != f.Verdict {
			continue
		}
		c := t.clone()
		if c.Report != nil {
			c.Verdict = string(c.Report.Verdict)
			c.Score = c.Report.Score
		}
		c.Report = nil // 列表不带完整报告，只保留结论摘要
		c.HasDynamic = c.Dynamic != nil
		c.Dynamic = nil // 列表不带动态详情
		all = append(all, c)
	}
	s.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total = len(all)
	if f.Offset > total {
		f.Offset = total
	}
	end := total
	if f.Limit > 0 && f.Offset+f.Limit < end {
		end = f.Offset + f.Limit
	}
	items = all[f.Offset:end]
	if items == nil {
		items = []*Task{}
	}
	return items, total
}

func (s *Store) Audit(e AuditEntry) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, _ := json.Marshal(e)
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if s.auditW != nil {
		s.auditW.Write(append(b, '\n'))
	}
}

// Audits 读回最近的审核日志（倒序，最多 limit 条）。
func (s *Store) Audits(limit int) ([]AuditEntry, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, "audit.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, err
	}
	var out []AuditEntry
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []AuditEntry{}
	}
	return out, nil
}

// Delete 删除单个任务：内存记录 + 任务 JSON + 上传原文件 + bySHA 反查。
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	t := s.tasks[id]
	if t == nil {
		s.mu.Unlock()
		return ErrNotFound
	}
	delete(s.tasks, id)
	if s.bySHA[t.SHA256] == id {
		delete(s.bySHA, t.SHA256)
	}
	sha := t.SHA256
	s.mu.Unlock()
	os.Remove(filepath.Join(s.dir, "tasks", id+".json"))
	os.Remove(s.UploadPath(id))
	s.Audit(AuditEntry{TaskID: id, SHA256: sha, Action: "delete"})
	return nil
}

// DeleteAll 清空全部任务与记录：所有任务 JSON、上传文件、内存表，并清空 audit.jsonl。
// 返回删除的任务数。用于测试后重置或换正式令牌前清场。
func (s *Store) DeleteAll() (int, error) {
	s.mu.Lock()
	n := len(s.tasks)
	ids := make([]string, 0, n)
	for id := range s.tasks {
		ids = append(ids, id)
	}
	s.tasks = map[string]*Task{}
	s.bySHA = map[string]string{}
	s.mu.Unlock()

	for _, id := range ids {
		os.Remove(filepath.Join(s.dir, "tasks", id+".json"))
		os.Remove(s.UploadPath(id))
	}
	// 清空审核日志（"所有记录"）——截断当前文件，保持句柄可继续追加。
	s.auditMu.Lock()
	if s.auditW != nil {
		s.auditW.Truncate(0)
		s.auditW.Seek(0, 0)
	}
	s.auditMu.Unlock()
	s.Audit(AuditEntry{Action: "delete_all", Note: fmt.Sprintf("cleared %d tasks", n)})
	return n, nil
}

// ResetForRescan 把已完成的任务重置为待扫描：清掉旧报告/动态结果/审核裁决，State 回 queued。
// 上传原文件必须还在（供 worker 重扫）。返回重置后的任务克隆。调用方随后 Enqueue(id) 即重跑。
func (s *Store) ResetForRescan(id string) (*Task, error) {
	if _, err := os.Stat(s.UploadPath(id)); err != nil {
		return nil, fmt.Errorf("原始样本已不在，无法重扫: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tasks[id]
	if t == nil {
		return nil, ErrNotFound
	}
	t.State = Queued
	t.Report = nil
	t.Verdict, t.Score = "", 0
	t.Error = ""
	t.StartedAt, t.EndedAt = nil, nil
	t.Review, t.Reviewer, t.ReviewNote, t.ReviewedAt = Pending, "", "", nil
	t.Dynamic, t.HasDynamic = nil, false
	t.DynamicState, t.DynamicTarget, t.DynamicError = "", "", ""
	if err := s.persist(t); err != nil {
		return nil, err
	}
	s.Audit(AuditEntry{TaskID: id, SHA256: t.SHA256, Action: "rescan"})
	return t.clone(), nil
}

func (s *Store) persist(t *Task) error {
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "tasks", t.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// newID 生成时间有序、进程内唯一的任务 ID：<秒级时间戳36进制>-<序号36进制>。调用方须持有 s.mu。
func (s *Store) newID() string {
	s.seq++
	return fmt.Sprintf("%s-%s", strconv36(time.Now().UTC().Unix()), strconv36(int64(s.seq)))
}

func strconv36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%36]
		n /= 36
	}
	return string(b[i:])
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
