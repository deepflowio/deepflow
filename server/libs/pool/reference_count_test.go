package pool

import (
	"testing"
)

func TestReferenceCount(t *testing.T) {
	var r ReferenceCount
	r.Reset()

	r.AddReferenceCount()
	if r != 2 {
		t.Errorf("AddReferenceCount错误，预期为%d，实际为%d", 2, r)
	}
	v := r.GetReferenceCount()
	if v != 2 {
		t.Errorf("GetReferenceCount错误，预期为%d，实际为%d", 2, v)
	}

	valid := r.SubReferenceCount()
	if r != 1 || valid != true {
		t.Errorf("SubReferenceCount错误，预期为%d/%v，实际为%d/%v", 1, true, r, valid)
	}

	r.AddReferenceCount()
	r.Reset()
	if r != 1 {
		t.Errorf("Reset错误，预期为%d，实际为%d", 1, r)
	}

	valid = r.SubReferenceCount()
	if r != 0 || valid != false {
		t.Errorf("SubReferenceCount错误，预期为%d/%v，实际为%d/%v", 0, false, r, valid)
	}
	r.Reset()
	if r != 1 {
		t.Errorf("Reset错误，预期为%d，实际为%d", 1, r)
	}
}
