// Package worker 是扫描任务的后台队列：N 个 worker 从队列取任务，读回上传原文件做静态扫描，写回结果。
package worker

import (
	"fmt"
	"log"
	"os"
	"strings"

	"vpetmod-scanner/internal/scan"
	"vpetmod-scanner/internal/store"
)

type Pool struct {
	st       *store.Store
	lim      scan.Limits
	q        chan string
	workers  int
	done     chan struct{}
	autoDyn  bool            // 静态判恶意/可疑后是否自动入动态引爆队列
	triggers map[string]bool // 触发动态分析的静态结论集合
}

func New(st *store.Store, lim scan.Limits, workers, queueSize int) *Pool {
	if workers < 1 {
		workers = 1
	}
	if queueSize < workers {
		queueSize = workers
	}
	return &Pool{st: st, lim: lim, q: make(chan string, queueSize), workers: workers, done: make(chan struct{})}
}

// SetAutoDynamic 开启"静态命中即自动排动态分析"。triggers 为触发的结论集合（如 malicious/suspicious）。
func (p *Pool) SetAutoDynamic(on bool, triggers []string) {
	p.autoDyn = on
	p.triggers = map[string]bool{}
	for _, v := range triggers {
		p.triggers[v] = true
	}
}

func (p *Pool) Start() {
	for i := 0; i < p.workers; i++ {
		go p.loop()
	}
}

// Enqueue 把任务放进队列；队列已满返回 false（调用方应告知客户端稍后重试）。
func (p *Pool) Enqueue(id string) bool {
	select {
	case p.q <- id:
		return true
	default:
		return false
	}
}

// Stop 关闭队列并等待在跑的任务结束。
func (p *Pool) Stop() {
	close(p.q)
	for i := 0; i < p.workers; i++ {
		<-p.done
	}
}

func (p *Pool) loop() {
	defer func() { p.done <- struct{}{} }()
	for id := range p.q {
		p.run(id)
	}
}

func (p *Pool) run(id string) {
	p.st.MarkRunning(id)
	rep, err := p.scan(id)
	p.st.Finish(id, rep, err)
	if err != nil {
		log.Printf("task %s scan error: %v", id, err)
	} else if rep != nil {
		log.Printf("task %s: %s score=%d", id, rep.Verdict, rep.Score)
		if p.autoDyn && p.triggers[string(rep.Verdict)] {
			if target := DetonationTarget(rep); target != "" {
				p.st.EnqueueDynamic(id, target)
				log.Printf("task %s: 已排入自动动态分析 (target=%q)", id, target)
			} else {
				// 连一个原生 PE 都没有（纯资源包 / 仅托管插件）：原生 harness 无从引爆，跳过。
				log.Printf("task %s: %s 无可引爆的原生 PE，跳过动态分析", id, rep.Verdict)
			}
		}
	}
}

// DetonationTarget 决定动态引爆目标：优先结构命中的 boot/载荷（BootTarget），
// 命中为空时（clean/低分样本）兜底挑一个原生 PE。都没有则返回 ""（调用方跳过排队）。
// 自动动态队列和去重补排两条路都走这里，保证"低分也动态"的策略一致。
func DetonationTarget(rep *scan.Report) string {
	if t := BootTarget(rep); t != "" {
		return t
	}
	return fallbackNativePE(rep)
}

// BootTarget 从静态报告里挑出 boot 加载器的包内路径，供动态 worker 定位引爆目标。
// 优先级：boot 结构 > 加密载荷 > 明态载荷标记（PX-JS-INJECT / PX-ARTIFACT-MARKERS）> 无。
// 明态载荷（如 SteamCFyinxiao.dll）没有 overlay 也没有 boot，但它是真正干活的那个文件，
// 必须排在"随便挑一个原生 PE"之前。
func BootTarget(rep *scan.Report) string {
	pick := func(fs []scan.Finding) string {
		for _, f := range fs {
			if f.Rule == "PX-BOOT-EXPORT" || f.Rule == "PX-BOOT-TRAILER" {
				return f.Path
			}
		}
		for _, f := range fs {
			if f.Rule == "IOC-PE-BODY" || f.Rule == "PX-PAYLOAD" {
				return f.Path
			}
		}
		for _, f := range fs {
			if f.Rule == "PX-JS-INJECT" || f.Rule == "PX-ARTIFACT-MARKERS" || f.Rule == "IOC-PE-TEXT" {
				return f.Path
			}
		}
		return ""
	}
	for _, m := range rep.Mods {
		if t := pick(m.Findings); t != "" {
			return t
		}
	}
	return pick(rep.Loose)
}

// fallbackNativePE 为无结构命中的样本挑一个原生（非 .NET）PE 作引爆目标。
// 优先 native/ 目录下的（VPet 从不加载这里的 DLL，放这儿本身就可疑），其次 .dll 优先于 .exe。
// 只认原生 PE：托管 DLL 要靠 .NET 运行时 + VPet 宿主才能跑，本套原生 harness 无从引爆。
func fallbackNativePE(rep *scan.Report) string {
	best, bestScore := "", -1
	for _, f := range rep.Files {
		if f.Kind != "pe-native" {
			continue
		}
		lp := strings.ToLower(f.Path)
		score := 0
		if strings.Contains(lp, "/native/") || strings.Contains(lp, "\\native\\") {
			score += 2
		}
		if strings.HasSuffix(lp, ".dll") {
			score++
		}
		if score > bestScore {
			best, bestScore = f.Path, score
		}
	}
	return best
}

func (p *Pool) scan(id string) (rep *scan.Report, err error) {
	// 恶意样本本身不会被执行（纯静态解析），但解压库解析畸形输入可能 panic，兜住它。
	defer func() {
		if r := recover(); r != nil {
			rep, err = nil, fmt.Errorf("扫描器内部错误: %v", r)
		}
	}()

	t, gerr := p.st.Get(id)
	if gerr != nil {
		return nil, gerr
	}
	path := p.st.UploadPath(id)
	f, oerr := os.Open(path)
	if oerr != nil {
		return nil, oerr
	}
	defer f.Close()
	fi, serr := f.Stat()
	if serr != nil {
		return nil, serr
	}
	name := t.Filename
	if name == "" {
		name = id
	}
	return scan.ScanReader(name, f, fi.Size(), p.lim), nil
}
