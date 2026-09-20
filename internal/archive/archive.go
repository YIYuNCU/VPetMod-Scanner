// Package archive 把一个压缩包解成"文件名 → 字节"的成员序列。
// 只解压、绝不执行任何成员；只解一层，嵌套压缩包由调用方按深度再次调用。
// 支持 zip / 7z / rar / tar(.gz/.bz2/.xz) 以及单独的 .gz。
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"path"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/nwaples/rardecode/v2"
	"github.com/ulikunitz/xz"
)

type Options struct {
	MaxFileBytes int64 // 单个成员解压后上限；超过则跳过并 warn
	Warn         func(format string, a ...any)
}

func (o Options) warn(format string, a ...any) {
	if o.Warn != nil {
		o.Warn(format, a...)
	}
}

// Sniff 返回压缩包类型（zip/7z/rar/tar/gz/bz2/xz），无法识别返回空串。
func Sniff(b []byte) string {
	switch {
	case len(b) >= 4 && string(b[:4]) == "PK\x03\x04",
		len(b) >= 4 && string(b[:4]) == "PK\x05\x06": // 空 zip
		return "zip"
	case len(b) >= 6 && string(b[:6]) == "7z\xbc\xaf\x27\x1c":
		return "7z"
	case len(b) >= 7 && string(b[:7]) == "Rar!\x1a\x07\x00",
		len(b) >= 8 && string(b[:8]) == "Rar!\x1a\x07\x01\x00": // RAR5
		return "rar"
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gz"
	case len(b) >= 3 && string(b[:3]) == "BZh":
		return "bz2"
	case len(b) >= 6 && string(b[:6]) == "\xfd7zXZ\x00":
		return "xz"
	case len(b) >= 262 && string(b[257:262]) == "ustar":
		return "tar"
	}
	return ""
}

// IsArchive 报告 b 是否为受支持的压缩包。
func IsArchive(b []byte) bool { return Sniff(b) != "" }

// Walk 解出 name 指向的压缩包的每个常规文件成员，逐个调用 emit。
// handled=false 表示不是可识别的压缩包。
func Walk(name string, b []byte, opt Options, emit func(memberName string, data []byte)) (handled bool, err error) {
	kind := Sniff(b)
	if kind == "" {
		return false, nil
	}
	switch kind {
	case "zip":
		err = walkZip(b, opt, emit)
	case "7z":
		err = walk7z(b, opt, emit)
	case "rar":
		err = walkRar(b, opt, emit)
	case "tar":
		err = walkTar(bytes.NewReader(b), opt, emit)
	case "gz", "bz2", "xz":
		err = walkCompressed(name, kind, b, opt, emit)
	}
	return true, err
}

func walkZip(b []byte, opt Options, emit func(string, []byte)) error {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			opt.warn("%s: %v", f.Name, err)
			continue
		}
		readMember(f.Name, rc, opt, emit)
		rc.Close()
	}
	return nil
}

func walk7z(b []byte, opt Options, emit func(string, []byte)) error {
	zr, err := sevenzip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			opt.warn("%s: %v", f.Name, err)
			continue
		}
		readMember(f.Name, rc, opt, emit)
		rc.Close()
	}
	return nil
}

func walkRar(b []byte, opt Options, emit func(string, []byte)) error {
	rr, err := rardecode.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	for {
		hdr, err := rr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			opt.warn("rar: %v", err)
			return nil
		}
		if hdr.IsDir {
			continue
		}
		readMember(hdr.Name, rr, opt, emit)
	}
	return nil
}

func walkTar(r io.Reader, opt Options, emit func(string, []byte)) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			opt.warn("tar: %v", err)
			return nil
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		readMember(hdr.Name, tr, opt, emit)
	}
	return nil
}

// walkCompressed 处理单层压缩流：解压后若是 tar 就当 tar 走，否则视为单个文件。
func walkCompressed(name, kind string, b []byte, opt Options, emit func(string, []byte)) error {
	var r io.Reader
	switch kind {
	case "gz":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	case "bz2":
		r = bzip2.NewReader(bytes.NewReader(b))
	case "xz":
		zr, err := xz.NewReader(bytes.NewReader(b))
		if err != nil {
			return err
		}
		r = zr
	}
	// 解压后读进内存（上限 MaxFileBytes），据此判断是 tar 还是单文件。
	data, truncated := readLimited(r, opt.MaxFileBytes)
	if truncated {
		opt.warn("%s: 解压后超过 %d 字节上限，未分析", name, opt.MaxFileBytes)
		return nil
	}
	inner := strings.TrimSuffix(strings.TrimSuffix(path.Base(name), ".gz"), ".tgz")
	if len(data) >= 262 && string(data[257:262]) == "ustar" {
		return walkTar(bytes.NewReader(data), opt, emit)
	}
	emit(inner, data)
	return nil
}

func readMember(name string, r io.Reader, opt Options, emit func(string, []byte)) {
	data, truncated := readLimited(r, opt.MaxFileBytes)
	if truncated {
		opt.warn("%s: 解压后超过 %d 字节上限，未分析", name, opt.MaxFileBytes)
		return
	}
	emit(name, data)
}

// readLimited 读取至多 max 字节；返回是否被截断（即成员实际更大）。
func readLimited(r io.Reader, max int64) (data []byte, truncated bool) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false
	}
	if int64(len(b)) > max {
		return nil, true
	}
	return b, false
}
