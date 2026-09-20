// vpetscan：VPet MOD 恶意代码静态检测。
//
//	vpetscan scan [-json] <目录|zip|dll>...   本地扫描，退出码 0=干净 1=可疑 2=恶意 3=出错
//	vpetscan serve [-listen 127.0.0.1:8740] [-token T] [-allow-root DIR]...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"vpetmod-scanner/internal/api"
	"vpetmod-scanner/internal/scan"
)

var version = "0.1.0"

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(3)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "serve":
		runServe(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(3)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法:
  vpetscan scan [-json] <目录|zip|dll>...
  vpetscan serve [-listen 127.0.0.1:8740] [-token TOKEN] [-data DIR] [-workers 2] [-max-upload-mb 256] [-allow-root DIR]...
  vpetscan version

Steam 创意工坊 MOD 目录一般在 <Steam>\steamapps\workshop\content\1920960`)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "输出 JSON 报告")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		usage()
		return 3
	}
	worst := 0
	for _, p := range fs.Args() {
		rep, err := scan.ScanPath(p, scan.DefaultLimits())
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", p, err)
			worst = max(worst, 3)
			continue
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)
			_ = enc.Encode(rep)
		} else {
			printText(rep)
		}
		switch rep.Verdict {
		case scan.Malicious:
			worst = max(worst, 2)
		case scan.Suspicious:
			worst = max(worst, 1)
		}
	}
	return worst
}

var mark = map[scan.Verdict]string{scan.Malicious: "[恶意]", scan.Suspicious: "[可疑]", scan.Clean: "[干净]"}

func printText(rep *scan.Report) {
	fmt.Printf("%s %s  score=%d  files=%d  pe=%d\n", mark[rep.Verdict], rep.Target, rep.Score, rep.Scanned, len(rep.Files))
	for _, m := range rep.Mods {
		if m.Verdict == scan.Clean && len(m.Findings) == 0 {
			continue
		}
		fmt.Printf("\n  %s %s  (%s / %s)  score=%d\n", mark[m.Verdict], m.Root, m.Name, m.Author, m.Score)
		for _, f := range m.Findings {
			printFinding(f)
		}
	}
	if len(rep.Loose) > 0 {
		fmt.Println("\n  不属于任何 MOD 的发现:")
		for _, f := range rep.Loose {
			printFinding(f)
		}
	}
	for _, w := range rep.Warnings {
		fmt.Println("  ! " + w)
	}
	fmt.Println()
}

func printFinding(f scan.Finding) {
	fmt.Printf("    %-8s %-22s %s\n             %s\n", f.Severity, f.Rule, f.Title, f.Path)
	if f.Detail != "" {
		fmt.Printf("             %s\n", f.Detail)
	}
	for k, v := range f.Evidence {
		fmt.Printf("             %s=%s\n", k, v)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8740", "监听地址")
	token := fs.String("token", os.Getenv("VPETSCAN_TOKEN"), "Bearer 鉴权令牌（也可用环境变量 VPETSCAN_TOKEN）")
	maxMB := fs.Int64("max-upload-mb", 256, "单次上传上限 (MB)")
	dataDir := fs.String("data", "data", "任务与审核记录的存储目录")
	workers := fs.Int("workers", 2, "并行扫描 worker 数")
	queue := fs.Int("queue", 256, "扫描队列长度")
	autoDyn := fs.Bool("auto-dynamic", false, "静态判恶意/可疑后自动排动态分析队列（由外部 dynamic-worker 认领引爆）")
	dynTrig := fs.String("dynamic-triggers", "malicious,suspicious,clean", "触发自动动态分析的静态结论，逗号分隔。默认含 clean：静态干净不等于安全，含原生 PE 的样本一律动态复核，防新家族/加密载荷漏网（无原生 PE 的纯资源/托管包会自动跳过）")
	var roots multiFlag
	fs.Var(&roots, "allow-root", "允许服务端路径扫描的目录，可重复；不传则 /api/v1/scan/path 关闭")
	_ = fs.Parse(args)

	if *token == "" && !strings.HasPrefix(*listen, "127.0.0.1:") && !strings.HasPrefix(*listen, "localhost:") {
		log.Printf("警告：监听 %s 且未设置 -token，任何能访问该端口的人都能提交扫描和审核", *listen)
	}
	srv, err := api.New(api.Config{
		Listen:          *listen,
		Token:           *token,
		MaxUpload:       *maxMB << 20,
		DataDir:         *dataDir,
		Workers:         *workers,
		QueueSize:       *queue,
		AutoDynamic:     *autoDyn,
		DynamicTriggers: strings.Split(*dynTrig, ","),
		AllowRoots:      roots,
		Limits:          scan.DefaultLimits(),
		Version:         version,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	log.Fatal(srv.ListenAndServe())
}
