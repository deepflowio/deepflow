package timemap

import "strconv"

type TestEntry struct {
	timestamp uint32
	k         uint64
	v         uint64
}

func newTestEntry(t uint32, v int) Entry {
	e := TestEntry{
		timestamp: t,
		k:         uint64(v),
		v:         uint64(v),
	}
	return &e
}

func (e *TestEntry) Timestamp() uint32 {
	return e.timestamp
}

func (e *TestEntry) SetTimestamp(timestamp uint32) {
	e.timestamp = timestamp
}

func (e *TestEntry) Hash() uint64 {
	return e.k
}

func (e *TestEntry) Eq(other Entry) bool {
	return e.Hash() == other.Hash()
}

func (e *TestEntry) Merge(other Entry) {
	if o, ok := other.(*TestEntry); ok {
		e.v += o.v
	}
}

func (e *TestEntry) Clone() Entry {
	newEntry := *e
	return &newEntry
}

func (e *TestEntry) Release() {
}

func (e *TestEntry) String() string {
	return strconv.FormatUint(e.v, 10)
}
