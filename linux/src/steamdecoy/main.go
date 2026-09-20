//go:build windows

// steamdecoy：假 steam.exe 进程（良性，仅用于隔离沙箱诱饵）。构建产物必须命名为 steam.exe 使用。
// 依据：3803426816 载荷解密分析——plugin_8b 会枚举进程按名筛 steam.exe，OpenProcess 后
// ReadProcessMemory 搜 JWT 头部特征（eyJ…）。真实沙箱里没有 Steam，该路径永远拿不到数据、
// 也就不会走到外传。本诱饵把金丝雀化的假 JWT 铺进映像与堆内存：样本若真来读，外发内容里
// 就会出现唯一令牌（CANARY-…），与其它金丝雀同等级铁证。
// env: STEAM_DECOY_TOKEN=金丝雀令牌（缺省用占位串）。GOOS=windows GOARCH=amd64 交叉编译。
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	tok := os.Getenv("STEAM_DECOY_TOKEN")
	if tok == "" {
		tok = "CANARY-STEAM-DECOY-PLACEHOLDER"
	}
	// 多种 JWT 形态（头部/写法变体），提高命中不同特征匹配的概率。
	// 字面量直接编进 .rdata：进程一起映像内就有，不依赖堆分配。
	forms := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3NjU2MTE5OTk5OTk5OSIsImFjY291bnQiOiJjYW5hcnlfdXNlciIsInRvayI6Ii" + tok + "In0.kSAMPLE_SIG_SAMPLE_SIG_SAMPLE_SIG",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + tok + ".SIGNED_SAMPLE_SIGNATURE_PADDING",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkiLCJqdGkiOiI" + tok + "In0.ZQ",
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + tok + ".",
	}
	var heap [][]byte
	for _, f := range forms {
		// 堆上再铺 64 份拷贝，防只扫堆不扫映像的实现
		for j := 0; j < 64; j++ {
			b := make([]byte, len(f)+16)
			copy(b, f)
			heap = append(heap, b)
		}
	}
	fmt.Printf("[steam-decoy] 活着，JWT 诱饵 %d 形态 x64 已铺内存, token=%s\n", len(forms), tok)
	// 周期触碰防优化，也向 strace 证明诱饵一直存活
	for i := 0; ; i++ {
		n := 0
		for _, b := range heap {
			n += len(b)
		}
		if i%30 == 0 {
			fmt.Printf("[steam-decoy] alive heap=%d token=%s\n", n, tok)
		}
		time.Sleep(5 * time.Second)
	}
}
