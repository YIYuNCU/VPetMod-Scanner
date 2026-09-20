package store

import (
	"os"
	"testing"

	"vpetmod-scanner/internal/scan"
)

func mkStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func submit(t *testing.T, s *Store, name string, data []byte) *Task {
	t.Helper()
	task, _, err := s.Submit(name, "tester", data, true)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestDeleteRemovesTaskAndUpload(t *testing.T) {
	s := mkStore(t)
	task := submit(t, s, "a.dll", []byte("MZ payload"))
	up := s.UploadPath(task.ID)
	if _, err := os.Stat(up); err != nil {
		t.Fatalf("上传文件应存在: %v", err)
	}
	if err := s.Delete(task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(task.ID); err == nil {
		t.Fatal("删除后不应还能 Get 到任务")
	}
	if _, err := os.Stat(up); !os.IsNotExist(err) {
		t.Fatal("删除后上传文件应被清除")
	}
	if err := s.Delete("nope"); err != ErrNotFound {
		t.Fatalf("删不存在的任务应返回 ErrNotFound，got %v", err)
	}
}

func TestDeleteAllClears(t *testing.T) {
	s := mkStore(t)
	submit(t, s, "a.dll", []byte("MZ a"))
	submit(t, s, "b.dll", []byte("MZ b"))
	n, err := s.DeleteAll()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应清空 2 个任务，got %d", n)
	}
	if items, total := s.List(ListFilter{}); total != 0 || len(items) != 0 {
		t.Fatalf("清空后列表应为空，got total=%d", total)
	}
}

func TestResetForRescan(t *testing.T) {
	s := mkStore(t)
	task := submit(t, s, "a.dll", []byte("MZ payload"))
	// 模拟已完成 + 已审核 + 有动态结果
	s.Finish(task.ID, &scan.Report{Verdict: scan.Malicious, Score: 100}, nil)
	s.SetReview(task.ID, Approved, "qa", "ok")
	s.SetDynamic(task.ID, &DynamicReport{Verdict: "clean"})

	rt, err := s.ResetForRescan(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rt.State != Queued {
		t.Fatalf("重扫后 State 应回 queued，got %s", rt.State)
	}
	if rt.Report != nil || rt.Review != Pending || rt.Dynamic != nil || rt.DynamicState != "" {
		t.Fatalf("重扫应清掉旧报告/审核/动态：%+v", rt)
	}
	// 上传文件被删后不能重扫
	os.Remove(s.UploadPath(task.ID))
	if _, err := s.ResetForRescan(task.ID); err == nil {
		t.Fatal("样本已删应无法重扫")
	}
}
