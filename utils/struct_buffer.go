package utils

// 适用于存放可重用的、小规模对象
type StructBuffer struct {
	items []interface{}
	next  int
	New   func() interface{}
}

func (b *StructBuffer) Slice() []interface{} {
	return b.items[:b.next]
}

func (b *StructBuffer) Get() interface{} {
	if b.next == len(b.items) {
		b.items = append(b.items, b.New())
	}
	b.next++
	return b.items[b.next-1]
}

func (b *StructBuffer) Reset() {
	b.next = 0
}
