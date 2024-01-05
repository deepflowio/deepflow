//go:build linux && xdp
// +build linux,xdp

/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package xdppacket

import (
	"fmt"
	"unsafe"

	"github.com/textnode/fencer"
	"golang.org/x/sys/unix"
)

// 循环队列结构
type BaseQueue struct {
	// Mmap返回值
	raw []byte
	// 对应raw的起始地址
	baseAddr uint64
	// 生产者指针
	producer *uint32
	// 消费者指针
	consumer *uint32

	cached_pro uint32
	cached_con uint32
	// 队列大小
	size uint32
	// 队列大小掩码
	mask uint32

	// 内部数据，为优化性能添加
	idx     uint32
	entries uint32
}

type XDPUmemQueue struct {
	BaseQueue
	// UMEM实际数据存放的起始地址
	ring *uint64
}

type XDPDescQueue struct {
	BaseQueue
	// XDPDesc实际数据存放起始地址
	ring *unix.XDPDesc
}

func getSliceAddr(data []byte) uint64 {
	return uint64(uintptr(unsafe.Pointer(&data[0])))
}

func Uint32Min(x, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

// 计算队列剩余条目数
func (q *BaseQueue) cachedFreeEntries() uint32 {
	return q.size - (q.cached_pro - q.cached_con)
}

// 计算队列条目数
func (q *BaseQueue) cachedAvailEntries() uint32 {
	return q.cached_pro - q.cached_con
}

// 从队列中取n个剩余条目，如果队列剩余条目数小于n，则
// 返回队列当前剩余条目数
func (q *BaseQueue) freeEntries(n uint32) uint32 {
	if q.cachedFreeEntries() >= n {
		return n
	}
	q.cached_con = *q.consumer

	return Uint32Min(q.cachedFreeEntries(), n)
}

// 从队列中取n个条目，如果队列条目数小于n，则
// 返回队列当前条目数
func (q *BaseQueue) getAvailEntries(n uint32) uint32 {
	if q.cachedAvailEntries() >= n {
		return n
	}
	q.cached_pro = *q.producer

	return Uint32Min(q.cachedAvailEntries(), n)
}

func ringProdSubmit(producer *uint32, cached_pro uint32) {
	// wmb()
	fencer.SFence()
	*producer = cached_pro
}

func ringConsRelease(consumer *uint32, cached_con uint32) {
	// rwmb()
	fencer.LFence()
	*consumer = cached_con
}

// 从DESC队列中取一个条目
func (q *XDPDescQueue) dequeueOne(desc *unix.XDPDesc) uint32 {
	q.entries = q.getAvailEntries(1)

	if q.entries > 0 {
		q.idx = q.cached_con & q.mask

		q.cached_con++

		*desc = *(*unix.XDPDesc)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(q.idx*uint32(unsafe.Sizeof(*desc))))))

		ringConsRelease(q.consumer, q.cached_con)
	}

	return q.entries
}

// 从DESC队列中取n个条目, 如果队列条目数小于n，则返回当前队列条目数
func (q *XDPDescQueue) dequeue(desc []unix.XDPDesc, n uint32) uint32 {
	q.entries = q.getAvailEntries(n)

	for i := uint32(0); i < q.entries; i++ {
		idx := (q.cached_con) & q.mask
		q.cached_con++
		desc[i] = *(*unix.XDPDesc)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(idx*uint32(unsafe.Sizeof(unix.XDPDesc{}))))))
	}

	if q.entries > 0 {
		ringConsRelease(q.consumer, q.cached_con)
	}

	return q.entries
}

func (q *XDPDescQueue) rollback() (unix.XDPDesc, uint32, uint32) {
	desc := unix.XDPDesc{}
	q.entries = q.getAvailEntries(1)

	if q.entries > 0 {
		q.cached_pro--
		q.idx = q.cached_pro & q.mask

		desc = *(*unix.XDPDesc)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(q.idx*uint32(unsafe.Sizeof(desc))))))

		ringProdSubmit(q.producer, q.cached_pro)
	}

	return desc, q.entries, q.idx
}

// 向Desc队列中存入一个条目
func (q *XDPDescQueue) enqueueOne(desc unix.XDPDesc) error {
	q.entries = q.freeEntries(1)
	if q.entries < 1 {
		return ErrTxQueueFull
	}

	q.idx = q.cached_pro & q.mask
	q.cached_pro++
	*(*unix.XDPDesc)(unsafe.Pointer(uintptr(unsafe.Pointer(q.ring)) +
		uintptr(q.idx*uint32(unsafe.Sizeof(desc))))) = desc

	ringProdSubmit(q.producer, q.cached_pro)

	return nil
}

// 向Desc队列中存入n个条目，如果队列剩余条目数小于n，
// 则返回队列当前剩余条目数
func (q *XDPDescQueue) enqueue(descs []unix.XDPDesc, n uint32) error {
	q.entries = q.freeEntries(n)
	if q.entries < n {
		return ErrTxQueueFull
	}

	for i := uint32(0); i < q.entries; i++ {
		q.idx = q.cached_pro & q.mask
		q.cached_pro++
		*(*unix.XDPDesc)(unsafe.Pointer(uintptr(unsafe.Pointer(q.ring)) +
			uintptr(q.idx*uint32(unsafe.Sizeof(unix.XDPDesc{}))))) = descs[i]
	}
	ringProdSubmit(q.producer, q.cached_pro)

	return nil
}

// 从UMEM队列中取一个条目
// func (u *XDPUmemQueue) dequeueOne(index *uint64) uint32 {
func (u *XDPUmemQueue) dequeueOne(index *uint64) {
	u.entries = u.getAvailEntries(1)

	if u.entries > 0 {
		u.idx = u.cached_con & u.mask
		u.cached_con++
		*index = *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
			uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0))))))

		ringConsRelease(u.consumer, u.cached_con)
	}
}

// 从UMEM队列中取n个条目，如果队列条目数小于n，则返回当前队列条目数
func (u *XDPUmemQueue) dequeue(index []uint64, n uint32) uint32 {
	u.entries = u.getAvailEntries(n)

	for i := uint32(0); i < u.entries; i++ {
		u.idx = (u.cached_con) & u.mask
		u.cached_con++
		index[i] = *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
			uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0))))))
	}

	if u.entries > 0 {
		ringConsRelease(u.consumer, u.cached_con)
	}

	return u.entries
}

// 向UMEM队列中存入一个条目
func (u *XDPUmemQueue) enqueueOne(addr uint64) error {
	u.entries = u.freeEntries(1)
	if u.entries < 1 {
		return ErrFqQueueFull
	}

	u.idx = u.cached_pro & u.mask
	u.cached_pro++

	*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
		uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0)))))) = addr

	ringProdSubmit(u.producer, u.cached_pro)

	return nil
}

// 向UMEM队列中存入n个条目，如果队列剩余条目数小于n,
// 则返回队列当前剩余条目数
func (u *XDPUmemQueue) enqueue(addr []uint64, n uint32) error {
	u.entries = u.freeEntries(n)
	if u.entries < n {
		return ErrFqQueueFull
	}

	for i := uint32(0); i < u.entries; i++ {
		u.idx = u.cached_pro & u.mask
		u.cached_pro++

		*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
			uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0)))))) = addr[i]
	}

	ringProdSubmit(u.producer, u.cached_pro)

	return nil
}

// 初始化队列
func (q *BaseQueue) init(addr []byte, offset unix.XDPRingOffset, ringSize int) {
	q.raw = addr
	q.baseAddr = getSliceAddr(addr)
	q.producer = (*uint32)(unsafe.Pointer(uintptr(q.baseAddr + offset.Producer)))
	q.consumer = (*uint32)(unsafe.Pointer(uintptr(q.baseAddr + offset.Consumer)))

	q.cached_pro = 0
	q.cached_con = 0
	q.size = uint32(ringSize)
	q.mask = q.size - 1

	q.idx = 0
	q.entries = 0
}

func (q *BaseQueue) clear() {
	unix.Munmap(q.raw)
	*q = BaseQueue{}
}

func (u *XDPUmemQueue) initQueue(addr []byte, offset unix.XDPRingOffset, ringSize int) {
	u.init(addr, offset, ringSize)
	u.ring = (*uint64)(unsafe.Pointer(uintptr(u.baseAddr + offset.Desc)))
}

func (u *XDPUmemQueue) clearQueue() {
	u.ring = nil
	u.clear()
}

func (d *XDPDescQueue) initQueue(addr []byte, offset unix.XDPRingOffset, ringSize int) {
	d.init(addr, offset, ringSize)
	d.ring = (*unix.XDPDesc)(unsafe.Pointer(uintptr(d.baseAddr + offset.Desc)))
}

func (u *XDPDescQueue) clearQueue() {
	u.ring = nil
	u.clear()
}

func (q BaseQueue) String() string {
	return fmt.Sprintf("raw:%p, baseAddr:%x, producer:%v, consumer:%v, "+
		"cached_pro:%v, cached_con:%v, size:%v, mask:%v", q.raw, q.baseAddr,
		*q.producer, *q.consumer, q.cached_pro, q.cached_con, q.size, q.mask)
}

func (d XDPDescQueue) String() string {
	return fmt.Sprintf("ring:%p, %v", d.ring, d.BaseQueue)
}

func (u XDPUmemQueue) String() string {
	return fmt.Sprintf("ring:%p, %v", u.ring, u.BaseQueue)
}

func (q XDPUmemQueue) GetDetail() string {
	var str string
	var umemOffset uint64
	for i := uint32(0); i < q.size; i++ {
		umemOffset = *(*uint64)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(i*uint32(unsafe.Sizeof(uint64(0)))))))
		str += fmt.Sprintf("index:%v, offset:0x%x\t", i, umemOffset)
		if i&0x1 == 0x1 {
			str += "\n"
		}
	}
	return str
}

func (q XDPDescQueue) GetDetail() string {
	var str string
	var desc unix.XDPDesc
	for i := uint32(0); i < q.size; i++ {
		desc = *(*unix.XDPDesc)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(i*uint32(unsafe.Sizeof(unix.XDPDesc{}))))))
		str += fmt.Sprintf("\tindex:%v, desc--Addr:%v, Len:%v\t", i, desc.Addr, desc.Len)
		if i&0x1 == 0x1 {
			str += "\n"
		}
	}
	return str
}
