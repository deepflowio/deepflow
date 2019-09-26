// +build linux,xdp

package xdppacket

import (
	"fmt"
	"sync/atomic"
	"unsafe"

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
	i       uint32
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
	q.cached_con = atomic.LoadUint32(q.consumer)

	return Uint32Min(q.cachedFreeEntries(), n)
}

// 从队列中取n个条目，如果队列条目数小于n，则
// 返回队列当前条目数
func (q *BaseQueue) getAvailEntries(n uint32) uint32 {
	if q.cachedAvailEntries() >= n {
		return n
	}
	q.cached_pro = atomic.LoadUint32(q.producer)

	return Uint32Min(q.cachedAvailEntries(), n)
}

// 从DESC队列中取一个条目
func (q *XDPDescQueue) dequeueOne(desc *unix.XDPDesc) uint32 {
	q.entries = q.getAvailEntries(1)

	if q.entries > 0 {
		q.idx = q.cached_con & q.mask

		q.cached_con += 1

		*desc = *(*unix.XDPDesc)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(q.idx*uint32(unsafe.Sizeof(*desc))))))

		atomic.StoreUint32(q.consumer, q.cached_con)
	}

	return q.entries
}

// 从DESC队列中取n个条目, 如果队列条目数小于n，则返回当前队列条目数
func (q *XDPDescQueue) dequeue(desc []unix.XDPDesc, n uint32) uint32 {
	q.entries = q.getAvailEntries(n)

	for q.i = uint32(0); q.i < q.entries; q.i++ {
		idx := (q.cached_con) & q.mask
		q.cached_con += 1
		desc[q.i] = *(*unix.XDPDesc)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(idx*uint32(unsafe.Sizeof(unix.XDPDesc{}))))))
	}

	if q.entries > 0 {
		atomic.StoreUint32(q.consumer, q.cached_con)
	}

	return q.entries
}

func (q *XDPDescQueue) rollback() (unix.XDPDesc, uint32, uint32) {
	desc := unix.XDPDesc{}
	q.entries = q.getAvailEntries(1)

	if q.entries > 0 {
		q.cached_pro -= 1
		q.idx = q.cached_pro & q.mask

		desc = *(*unix.XDPDesc)(unsafe.Pointer((uintptr(unsafe.Pointer(q.ring)) +
			uintptr(q.idx*uint32(unsafe.Sizeof(desc))))))

		atomic.StoreUint32(q.producer, q.cached_pro)
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
	q.cached_pro += 1
	*(*unix.XDPDesc)(unsafe.Pointer(uintptr(unsafe.Pointer(q.ring)) +
		uintptr(q.idx*uint32(unsafe.Sizeof(desc))))) = desc

	atomic.StoreUint32(q.producer, q.cached_pro)

	return nil
}

// 向Desc队列中存入n个条目，如果队列剩余条目数小于n，
// 则返回队列当前剩余条目数
func (q *XDPDescQueue) enqueue(descs []unix.XDPDesc, n uint32) error {
	q.entries = q.freeEntries(n)
	if q.entries < n {
		return ErrTxQueueFull
	}

	for q.i = uint32(0); q.i < q.entries; q.i++ {
		q.idx = q.cached_pro & q.mask
		q.cached_pro += 1
		*(*unix.XDPDesc)(unsafe.Pointer(uintptr(unsafe.Pointer(q.ring)) +
			uintptr(q.idx*uint32(unsafe.Sizeof(unix.XDPDesc{}))))) = descs[q.i]
	}
	atomic.StoreUint32(q.producer, q.cached_pro)

	return nil
}

// 从UMEM队列中取一个条目
//func (u *XDPUmemQueue) dequeueOne(index *uint64) uint32 {
func (u *XDPUmemQueue) dequeueOne(index *uint64) {
	u.entries = u.getAvailEntries(1)

	if u.entries > 0 {
		u.idx = u.cached_con & u.mask
		u.cached_con += 1
		*index = *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
			uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0))))))

		atomic.StoreUint32(u.consumer, u.cached_con)
	}
}

// 从UMEM队列中取n个条目，如果队列条目数小于n，则返回当前队列条目数
func (u *XDPUmemQueue) dequeue(index []uint64, n uint32) uint32 {
	u.entries = u.getAvailEntries(n)

	for u.i = uint32(0); u.i < u.entries; u.i++ {
		u.idx = (u.cached_con) & u.mask
		u.cached_con += 1
		index[u.i] = *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
			uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0))))))
	}

	if u.entries > 0 {
		atomic.StoreUint32(u.consumer, u.cached_con)
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
	u.cached_pro += 1

	*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
		uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0)))))) = addr

	atomic.StoreUint32(u.producer, u.cached_pro)

	return nil
}

// 向UMEM队列中存入n个条目，如果队列剩余条目数小于n,
// 则返回队列当前剩余条目数
func (u *XDPUmemQueue) enqueue(addr []uint64, n uint32) error {
	u.entries = u.freeEntries(n)
	if u.entries < n {
		return ErrFqQueueFull
	}

	for u.i = uint32(0); u.i < u.entries; u.i++ {
		u.idx = u.cached_pro & u.mask
		u.cached_pro += 1

		*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(u.ring)) +
			uintptr(u.idx*uint32(unsafe.Sizeof(uint64(0)))))) = addr[u.i]
	}
	atomic.StoreUint32(u.producer, u.cached_pro)

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
