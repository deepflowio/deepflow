package datatype

import (
	"testing"
)

func compareGroupSlice(v, exp [][]int32) bool {
	if len(v) != 2 || len(exp) != 2 {
		return false
	}
	for i := range v {
		if len(v[i]) != len(exp[i]) {
			return false
		}
		for j := range v[i] {
			if v[i][j] != exp[i][j] {
				return false
			}
		}
	}
	return true
}

func TestFillGroupID_1(t *testing.T) {
	aclGidbitmap0 := AclGidBitmap(0)
	aclGidbitmap0.SetSrcFlag()
	aclGidbitmap0.SetMapOffset(0)

	aclGidbitmap1 := AclGidBitmap(0)
	aclGidbitmap1.SetDstFlag()
	aclGidbitmap1.SetMapOffset(0)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(2)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{5, 6}, []int32{7, 8}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap0, aclGidbitmap1}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{}, []int32{}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_2(t *testing.T) {
	aclGidbitmap0 := AclGidBitmap(0)
	aclGidbitmap0.SetSrcFlag()
	aclGidbitmap0.SetMapOffset(0)
	aclGidbitmap0.SetMapBits(0)

	aclGidbitmap1 := AclGidBitmap(0)
	aclGidbitmap1.SetDstFlag()
	aclGidbitmap1.SetMapOffset(0)
	aclGidbitmap1.SetMapBits(0)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(2)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap0, aclGidbitmap1}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{1}, []int32{3}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x1, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_3(t *testing.T) {
	aclGidbitmap0 := AclGidBitmap(0)
	aclGidbitmap0.SetSrcFlag()
	aclGidbitmap0.SetMapOffset(0)
	aclGidbitmap0.SetMapBits(0)
	aclGidbitmap0.SetMapBits(1)
	aclGidbitmap1 := AclGidBitmap(0)
	aclGidbitmap1.SetDstFlag()
	aclGidbitmap1.SetMapOffset(0)
	aclGidbitmap1.SetMapBits(0)
	aclGidbitmap1.SetMapBits(1)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(2)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap0, aclGidbitmap1}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{1, 2}, []int32{3, 4}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x3, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_4(t *testing.T) {
	aclGidbitmap0 := AclGidBitmap(0)
	aclGidbitmap0.SetSrcFlag()
	aclGidbitmap0.SetMapOffset(0)
	aclGidbitmap0.SetMapBits(1)

	aclGidbitmap1 := AclGidBitmap(0)
	aclGidbitmap1.SetDstFlag()
	aclGidbitmap1.SetMapOffset(0)
	aclGidbitmap1.SetMapBits(1)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(2)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap0, aclGidbitmap1}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{2}, []int32{4}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x2, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_5(t *testing.T) {

	aclGidbitmap0 := AclGidBitmap(0)
	aclGidbitmap0.SetSrcFlag()
	aclGidbitmap0.SetMapOffset(56) // 必须为56的倍数
	aclGidbitmap0.SetMapBits(0)

	aclGidbitmap1 := AclGidBitmap(0)
	aclGidbitmap1.SetDstFlag()
	aclGidbitmap1.SetMapOffset(56) // 必须为56的倍数
	aclGidbitmap1.SetMapBits(0)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(2)
	allGroupIDs := [][]uint32{[]uint32{}, []uint32{}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	for i := uint32(0); i < 56+2; i++ {
		allGroupIDs[0] = append(allGroupIDs[0], i)
		allGroupIDs[1] = append(allGroupIDs[1], 100+i)
	}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap0, aclGidbitmap1}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{56}, []int32{156}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("%v %v %v %v", aclGidbitmap0, aclGidbitmap1, aclGroupIDs, exp)
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x1, offset=1, expect %v, found %v", exp, aclGroupIDs)
	}
}
