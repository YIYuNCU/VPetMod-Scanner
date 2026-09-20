//go:build windows

// memprobe：沙箱诊断工具（良性）。复现 3803426816 plugin_8b 的跨进程读取路径——
// OpenProcess(QUERY|VM_READ) → VirtualQueryEx 枚举 → ReadProcessMemory——用来定位
// "VQ 成功但 RPM 全失败" 的 wine 层根因：逐区域打印 VQ 结果（base/size/state/protect）
// 与 RPM 结果（含 GetLastError），并在成功读到的数据里搜 eyJ（验证诱饵 JWT 猎杀可行性）。
// 只读我们自己拉起的诱饵进程，无写入/注入。GOOS=windows GOARCH=amd64 交叉编译。
// 用法: memprobe.exe <pid>    （pid 取诱饵就绪行 [steam-decoy] pid=…）
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	k32                 = syscall.NewLazyDLL("kernel32.dll")
	pOpenProcess        = k32.NewProc("OpenProcess")
	pVirtualQueryEx     = k32.NewProc("VirtualQueryEx")
	pReadProcessMemory  = k32.NewProc("ReadProcessMemory")
	pGetLastError       = k32.NewProc("GetLastError")
)

type mbi struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	_                 uint32 // 对齐填充（PartitionId+pad），x64 总尺寸 48
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

const (
	memCommit    = 0x1000
	pageNoAccess = 0x01
	pageGuard    = 0x100
)

func gle() uint32 {
	r, _, _ := pGetLastError.Call()
	return uint32(r)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: memprobe <pid>")
		os.Exit(2)
	}
	var pid uintptr
	fmt.Sscanf(os.Args[1], "%d", &pid)

	h, _, e := pOpenProcess.Call(0x410, 1, pid)
	if h == 0 {
		fmt.Printf("OpenProcess(%d) 失败: %v gle=%d\n", pid, e, gle())
		os.Exit(1)
	}
	fmt.Printf("OpenProcess(%d) → handle %#x\n", pid, h)

	var addr uintptr
	var nOK, nFail, bytesRead uint64
	eyJ := 0
	for i := 0; i < 100000; i++ {
		var m mbi
		r, _, _ := pVirtualQueryEx.Call(h, addr, uintptr(unsafe.Pointer(&m)), unsafe.Sizeof(m))
		if r == 0 {
			break
		}
		if m.RegionSize == 0 {
			break
		}
		if m.State == memCommit && m.Protect&(pageNoAccess|pageGuard) == 0 {
			// 先探 32 字节（区分"区域不可读"与"大块读失败"），再整块读
			var probe [32]byte
			var got uintptr
			ok, _, _ := pReadProcessMemory.Call(h, m.BaseAddress, uintptr(unsafe.Pointer(&probe[0])), 32, uintptr(unsafe.Pointer(&got)))
			probeStr := "ok"
			if ok == 0 {
				probeStr = fmt.Sprintf("FAIL gle=%d", gle())
			}
			n := uint64(0)
			for off := uintptr(0); off < m.RegionSize; off += 0x100000 {
				chunk := uintptr(0x100000)
				if m.RegionSize-off < chunk {
					chunk = m.RegionSize - off
				}
				buf := make([]byte, chunk)
				ok, _, _ := pReadProcessMemory.Call(h, m.BaseAddress+off, uintptr(unsafe.Pointer(&buf[0])), chunk, uintptr(unsafe.Pointer(&got)))
				if ok != 0 && got > 0 {
					nOK++
					n += uint64(got)
					if strings.Contains(string(buf[:got]), "eyJ") {
						eyJ++
					}
				} else {
					nFail++
				}
			}
			bytesRead += n
			fmt.Printf("region base=%#012x size=%#010x prot=%#06x type=%#06x probe32=%s fullread=%dB\n",
				m.BaseAddress, m.RegionSize, m.Protect, m.Type, probeStr, n)
		}
		next := m.BaseAddress + m.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	fmt.Printf("== 统计: RPM 成功块 %d / 失败块 %d, 共读 %d 字节, 含 eyJ 的块 %d ==\n", nOK, nFail, bytesRead, eyJ)
	if nOK == 0 {
		fmt.Println("== 结论: 全部 RPM 失败（与样本观察一致）——wine/沙箱层问题 ==")
	} else if eyJ == 0 {
		fmt.Println("== 结论: RPM 可用但未扫到 eyJ——诱饵内存布局问题 ==")
	} else {
		fmt.Println("== 结论: RPM 可用且能扫到 eyJ——样本侧扫描窗口/时限问题 ==")
	}
}
