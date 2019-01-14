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
	aclGidbitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapOffset(0).SetDstMapOffset(0)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{5, 6}, []int32{7, 8}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{}, []int32{}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_2(t *testing.T) {
	aclGidbitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapOffset(0).SetSrcMapBits(0)
	aclGidbitmap = aclGidbitmap.SetDstMapOffset(0).SetDstMapBits(0)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{1}, []int32{3}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x1, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_3(t *testing.T) {
	aclGidbitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapOffset(0).SetSrcMapBits(0).SetSrcMapBits(1)
	aclGidbitmap = aclGidbitmap.SetDstMapOffset(0).SetDstMapBits(0).SetDstMapBits(1)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{1, 2}, []int32{3, 4}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x3, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_4(t *testing.T) {
	aclGidbitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapOffset(0).SetSrcMapBits(1)
	aclGidbitmap = aclGidbitmap.SetDstMapOffset(0).SetDstMapBits(1)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	allGroupIDs := [][]uint32{[]uint32{1, 2}, []uint32{3, 4}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{2}, []int32{4}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x2, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestFillGroupID_5(t *testing.T) {

	aclGidbitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapOffset(24).SetSrcMapBits(0)
	aclGidbitmap = aclGidbitmap.SetDstMapOffset(24).SetDstMapBits(0)

	aclAction := AclAction(0).SetAclGidBitmapOffset(0).SetAclGidBitmapCount(1)
	allGroupIDs := [][]uint32{[]uint32{}, []uint32{}}
	aclGroupIDs := [][]int32{[]int32{}, []int32{}}

	for i := uint32(0); i < 24+2; i++ {
		allGroupIDs[0] = append(allGroupIDs[0], i)
		allGroupIDs[1] = append(allGroupIDs[1], 100+i)
	}

	FillGroupID(aclAction, []AclGidBitmap{aclGidbitmap}, allGroupIDs, aclGroupIDs)
	exp := [][]int32{[]int32{24}, []int32{124}}
	if !compareGroupSlice(aclGroupIDs, exp) {
		t.Errorf("%v %v %v", aclGidbitmap, aclGroupIDs, exp)
		t.Errorf("TestFillGroupID Check Failed: Mapbits=0x1, offset=1, expect %v, found %v", exp, aclGroupIDs)
	}
}

func TestReverseGroupType(t *testing.T) {
	aclGidBitmap := AclGidBitmap(0).SetSrcAndDstFlag().SetSrcMapOffset(0).SetSrcMapBits(2)
	aclGidBitmap = aclGidBitmap.SetDstMapOffset(24).SetDstMapBits(4)
	basicAclGidBitmap := aclGidBitmap
	aclGidBitmap.ReverseGroupType()
	if aclGidBitmap.GetSrcMapOffset() != basicAclGidBitmap.GetDstMapOffset() ||
		aclGidBitmap.GetSrcMapBits() != basicAclGidBitmap.GetDstMapBits() {
		t.Errorf("ReverseGroupType Failed: reverseAclGidBitmap(%v) basicAclGidBitmap(%v)", aclGidBitmap, basicAclGidBitmap)
	}
}
