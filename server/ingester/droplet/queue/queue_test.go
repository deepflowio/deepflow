package queue

import (
	"testing"
)

func TestQueue(t *testing.T) {
	buffer := make([]interface{}, 10)
	m := NewManager(1)

	q := m.NewQueue("1", 1024)
	q.Put(1)
	q.Put(2)
	q.Put(3)
	if q.Len() != 3 {
		t.Errorf("Len expect 3 actual %v", q.Len())
	}
	q.Get()
	n := q.Gets(buffer)
	if n != 2 {
		t.Errorf("Gets expect 2 actual %v", n)
	}
}
