// Package pe 对 PE 文件做纯静态解析：节、overlay、导出名、导入表是否存在、
// 节熵，以及 .NET 元数据的 #Strings / #US 堆。全程只读字节，不加载、不执行。
package pe

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"unicode/utf16"
)

const (
	dirExport   = 0
	dirImport   = 1
	dirSecurity = 4
	dirCLR      = 14
)

type Section struct {
	Name       string
	RawOffset  uint32
	RawSize    uint32
	VirtAddr   uint32
	VirtSize   uint32
	Executable bool
	Entropy    float64
	SHA256     string
}

type Info struct {
	Is64       bool
	IsDLL      bool
	Sections   []Section
	// ImportsReadable：导入表存在且首个描述符的 DLL 名是合法 ASCII。
	// 加密载荷的导入目录项照常填着，但指向的内容是密文，据此区分。
	ImportsReadable bool
	HasCert         bool

	// ExportName 是导出目录里记录的"原始 DLL 名"，改文件名改不掉它。
	ExportName string
	ExportCnt  int

	// Overlay 是最后一个节之后、签名之前的附加数据。
	OverlayOffset int
	Overlay       []byte
	// BodySHA256 = 去掉 overlay 后的哈希；变形样本通常只改 overlay。
	BodySHA256 string

	IsDotNet bool
	// .NET 元数据堆：#Strings 放类型/方法/模块名，#US 放代码里的字符串字面量。
	MetaStrings []string
	UserStrings []string
}

func (i *Info) Section(name string) *Section {
	for k := range i.Sections {
		if i.Sections[k].Name == name {
			return &i.Sections[k]
		}
	}
	return nil
}

func (i *Info) HasMetaString(s string) bool {
	for _, v := range i.MetaStrings {
		if v == s {
			return true
		}
	}
	return false
}

// IsPE 只看 MZ 头 + e_lfanew 指向的 PE 签名，用来决定要不要走完整解析。
func IsPE(b []byte) bool {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	off := int(binary.LittleEndian.Uint32(b[0x3c:]))
	return off > 0 && off+4 <= len(b) && bytes.Equal(b[off:off+4], []byte("PE\x00\x00"))
}

func Parse(b []byte) (*Info, error) {
	if !IsPE(b) {
		return nil, errors.New("not a PE file")
	}
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := &Info{IsDLL: f.Characteristics&pe.IMAGE_FILE_DLL != 0}
	var dirs []pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		info.Is64 = true
		dirs = oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	case *pe.OptionalHeader32:
		dirs = oh.DataDirectory[:oh.NumberOfRvaAndSizes]
	}
	dir := func(i int) pe.DataDirectory {
		if i < len(dirs) {
			return dirs[i]
		}
		return pe.DataDirectory{}
	}

	end := 0
	for _, s := range f.Sections {
		sec := Section{
			Name:       s.Name,
			RawOffset:  s.Offset,
			RawSize:    s.Size,
			VirtAddr:   s.VirtualAddress,
			VirtSize:   s.VirtualSize,
			Executable: s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0,
		}
		if lo, hi := int(s.Offset), int(s.Offset)+int(s.Size); s.Size > 0 && hi <= len(b) {
			data := b[lo:hi]
			sec.Entropy = Entropy(data)
			sec.SHA256 = sha256Hex(data)
			if hi > end {
				end = hi
			}
		}
		info.Sections = append(info.Sections, sec)
	}

	// 安全目录的 VirtualAddress 是文件偏移而非 RVA；签名块不算 overlay。
	tail := len(b)
	if sd := dir(dirSecurity); sd.Size > 0 {
		info.HasCert = true
		if int(sd.VirtualAddress) >= end && int(sd.VirtualAddress) < tail {
			tail = int(sd.VirtualAddress)
		}
	}
	if end > 0 && end < tail {
		info.OverlayOffset = end
		info.Overlay = b[end:tail]
	}
	if end > 0 && end <= len(b) {
		info.BodySHA256 = sha256Hex(b[:end])
	}

	rva := func(r uint32) int {
		for _, s := range info.Sections {
			span := s.VirtSize
			if s.RawSize > span {
				span = s.RawSize
			}
			if r >= s.VirtAddr && r < s.VirtAddr+span {
				off := int(r-s.VirtAddr) + int(s.RawOffset)
				if off < len(b) {
					return off
				}
			}
		}
		return -1
	}

	if id := dir(dirImport); id.Size >= 20 {
		if off := rva(id.VirtualAddress); off >= 0 && off+20 <= len(b) {
			if n := rva(binary.LittleEndian.Uint32(b[off+12:])); n >= 0 {
				info.ImportsReadable = isDLLName(cString(b[n:], 256))
			}
		}
	}

	if ed := dir(dirExport); ed.Size >= 40 {
		if off := rva(ed.VirtualAddress); off >= 0 && off+40 <= len(b) {
			info.ExportCnt = int(binary.LittleEndian.Uint32(b[off+20:]))
			if n := rva(binary.LittleEndian.Uint32(b[off+12:])); n >= 0 {
				info.ExportName = cString(b[n:], 256)
			}
		}
	}

	if cd := dir(dirCLR); cd.Size >= 16 {
		if off := rva(cd.VirtualAddress); off >= 0 && off+16 <= len(b) {
			mdRVA := binary.LittleEndian.Uint32(b[off+8:])
			mdSize := binary.LittleEndian.Uint32(b[off+12:])
			if mo := rva(mdRVA); mo >= 0 && mo+int(mdSize) <= len(b) {
				info.IsDotNet = true
				parseMetadata(b[mo:mo+int(mdSize)], info)
			}
		}
	}
	return info, nil
}

// parseMetadata 解析 ECMA-335 II.24.2 的元数据根，只取两个字符串堆。
func parseMetadata(md []byte, info *Info) {
	if len(md) < 20 || binary.LittleEndian.Uint32(md) != 0x424A5342 {
		return
	}
	verLen := int(binary.LittleEndian.Uint32(md[12:]))
	p := 16 + verLen
	if p+4 > len(md) {
		return
	}
	n := int(binary.LittleEndian.Uint16(md[p+2:]))
	p += 4
	for i := 0; i < n && p+8 < len(md); i++ {
		so := int(binary.LittleEndian.Uint32(md[p:]))
		ss := int(binary.LittleEndian.Uint32(md[p+4:]))
		name := cString(md[p+8:], 32)
		p += 8 + (len(name)+4)&^3
		if so < 0 || ss < 0 || so+ss > len(md) {
			continue
		}
		heap := md[so : so+ss]
		switch name {
		case "#Strings":
			for _, s := range bytes.Split(heap, []byte{0}) {
				if len(s) > 0 {
					info.MetaStrings = append(info.MetaStrings, string(s))
				}
			}
		case "#US":
			info.UserStrings = parseUserStrings(heap)
		}
	}
}

// #US 堆每项 = 压缩长度前缀 + UTF-16LE + 1 字节尾标记。
func parseUserStrings(h []byte) []string {
	var out []string
	for p := 1; p < len(h); {
		l, hdr := blobLen(h[p:])
		if hdr == 0 {
			break
		}
		p += hdr
		if l == 0 {
			continue
		}
		if p+l > len(h) {
			break
		}
		raw := h[p : p+l]
		if l%2 == 1 { // 正常情况：去掉尾标记字节
			raw = raw[:l-1]
		}
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		out = append(out, string(utf16.Decode(u)))
		p += l
	}
	return out
}

func blobLen(b []byte) (n, hdr int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch {
	case b[0]&0x80 == 0:
		return int(b[0]), 1
	case b[0]&0xC0 == 0x80 && len(b) >= 2:
		return int(b[0]&0x3F)<<8 | int(b[1]), 2
	case b[0]&0xE0 == 0xC0 && len(b) >= 4:
		return int(b[0]&0x1F)<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3]), 4
	}
	return 0, 0
}

func cString(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func isDLLName(s string) bool {
	if len(s) < 5 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	l := strings.ToLower(s)
	return strings.HasSuffix(l, ".dll") || strings.HasSuffix(l, ".drv") || strings.HasSuffix(l, ".sys") || strings.HasSuffix(l, ".exe")
}

func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var c [256]int
	for _, x := range b {
		c[x]++
	}
	e, n := 0.0, float64(len(b))
	for _, v := range c {
		if v > 0 {
			p := float64(v) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
