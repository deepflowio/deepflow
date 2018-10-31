package datatype

import (
	"sync/atomic"
)

type ReferenceCount int32

type ReferenceCounter interface {
	Init()
	AddReferenceCount()
	SubReferenceCount() bool
}

func (r *ReferenceCount) Init() {
	*r = 1
}

func (r *ReferenceCount) AddReferenceCount() {
	atomic.AddInt32((*int32)(r), 1)
}

func (r *ReferenceCount) SubReferenceCount() bool {
	if atomic.AddInt32((*int32)(r), -1) > 0 {
		return true
	}
	return false
}
