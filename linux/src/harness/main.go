//go:build windows

// harness：在 Wine 下复现 .NET 桩触发 boot 加载器的动作——LoadLibrary(boot) 后按序号 #1 调用。
// 真正的恶意行为（解密载荷、联网、读文件）都在 boot/载荷里，由此触发，再用 strace/tcpdump/sinkhole 观测。
// 仅用于隔离沙箱中对已捕获样本做分析。GOOS=windows GOARCH=amd64 交叉编译，wine64 harness.exe <boot.dll> [ordinal]
//
// env SPAWN_DECOY=<path>：先拉起诱饵进程（steam.exe 假进程，金丝雀化 JWT 铺内存），等 1 秒再
// 触发 boot——3803426816 的载荷按名枚举 steam.exe 并读其内存，没有诱饵时该窃密路径永远空跑。
// env STEAM_DECOY_TOKEN 透传给诱饵。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: harness.exe <boot.dll 路径> [导出序号,默认1]")
		os.Exit(2)
	}
	dll := os.Args[1]
	ord := uintptr(1)
	if len(os.Args) > 2 {
		if n, err := strconv.Atoi(os.Args[2]); err == nil {
			ord = uintptr(n)
		}
	}

	var decoy *os.Process
	if p := os.Getenv("SPAWN_DECOY"); p != "" {
		cmd := exec.Command(p)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), "STEAM_DECOY_TOKEN="+os.Getenv("STEAM_DECOY_TOKEN"))
		if err := cmd.Start(); err != nil {
			fmt.Printf("[harness] 诱饵 %s 启动失败: %v（继续，仅少一路观测）\n", p, err)
		} else {
			decoy = cmd.Process
			fmt.Printf("[harness] 诱饵已拉起 pid=%d，等 1s 就绪\n", decoy.Pid)
			time.Sleep(1 * time.Second)
		}
	}
	defer func() {
		if decoy != nil {
			_ = decoy.Kill()
		}
	}()

	fmt.Printf("[harness] LoadLibrary %s\n", dll)
	h, err := syscall.LoadLibrary(dll)
	if err != nil {
		fmt.Printf("[harness] LoadLibrary 失败: %v\n", err)
		os.Exit(1)
	}
	// 按序号取导出地址（lpProcName < 0x10000 表示按序号）
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getProc := k32.NewProc("GetProcAddress")
	addr, _, _ := getProc.Call(uintptr(h), ord)
	if addr == 0 {
		fmt.Printf("[harness] GetProcAddress #%d 失败\n", ord)
		os.Exit(1)
	}
	fmt.Printf("[harness] 调用 boot 导出 #%d @ %x\n", ord, addr)
	_, _, _ = syscall.SyscallN(addr) // boot 从自身 overlay 读配置，通常无需入参
	_ = unsafe.Pointer(nil)
	// 给后台线程/网络回连留出观测时间
	time.Sleep(20 * time.Second)
	fmt.Println("[harness] 完成")
}
