//go:build windows

// protectkey：DPAPI(CryptProtectData) 保护一小段明文，输出十六进制 blob。
// 用途：3803426816 的 plugin_8b 读 %LOCALAPPDATA%\Steam\local.vdf 的 ConnectCache 条目并
// CryptUnprotectData 解密。沙箱里种"真实可解"的 DPAPI blob（同一 Wine 用户上下文保护/解密），
// 样本解密成功后金丝雀明文进入上传数据——外发即铁证。Wine crypt32 不可用时脚本会回退随机 blob
// （解密失败但读取/尝试行为仍被 strace 记录）。
// 用法: protectkey.exe <明文>   → stdout 为 hex；失败 exit 1。
// GOOS=windows GOARCH=amd64 交叉编译，在引爆用的同一 WINEPREFIX 下运行。
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	data   *byte
	length uint32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: protectkey.exe <明文>")
		os.Exit(2)
	}
	plain := []byte(os.Args[1])
	in := dataBlob{length: uint32(len(plain))}
	if len(plain) > 0 {
		in.data = &plain[0]
	}
	var out dataBlob
	crypt32 := syscall.NewLazyDLL("crypt32.dll")
	protect := crypt32.NewProc("CryptProtectData")
	r, _, err := protect.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		fmt.Fprintf(os.Stderr, "CryptProtectData 失败: %v\n", err)
		os.Exit(1)
	}
	blob := unsafe.Slice(out.data, out.length)
	fmt.Println(hex.EncodeToString(blob))
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	kernel32.NewProc("LocalFree").Call(uintptr(unsafe.Pointer(out.data)))
}
