package flowgenerator

import (
	"sync"
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type FlowState int

const (
	FLOW_STATE_RAW FlowState = iota
	FLOW_STATE_OPENING_1
	FLOW_STATE_OPENING_2
	FLOW_STATE_ESTABLISHED
	FLOW_STATE_CLOSING_TX1
	FLOW_STATE_CLOSING_TX2
	FLOW_STATE_CLOSING_RX1
	FLOW_STATE_CLOSING_RX2
	FLOW_STATE_CLOSED
	FLOW_STATE_RESET
	FLOW_STATE_EXCEPTION
)

type FlowExtra struct {
	taggedFlow   *TaggedFlow
	metaFlowPerf *MetaFlowPerf
	flowState    FlowState
	recentTime   time.Duration
	timeout      time.Duration
	reversed     bool
	circlePktGot bool
}

var flowExtraPool = sync.Pool{
	New: func() interface{} {
		return new(FlowExtra)
	},
}

func AcquireFlowExtra() *FlowExtra {
	return flowExtraPool.Get().(*FlowExtra)
}

func ReleaseFlowExtra(flowExtra *FlowExtra) {
	flowExtra.taggedFlow = nil
	if flowExtra.metaFlowPerf != nil {
		ReleaseMetaFlowPerf(flowExtra.metaFlowPerf)
		flowExtra.metaFlowPerf = nil
	}
	flowExtraPool.Put(flowExtra)
}

func CloneFlowExtra(flowExtra *FlowExtra) *FlowExtra {
	newFlowExtra := AcquireFlowExtra()
	*newFlowExtra = *flowExtra
	if flowExtra.metaFlowPerf != nil {
		newFlowExtra.metaFlowPerf = CloneMetaFlowPerf(flowExtra.metaFlowPerf)
	}
	return newFlowExtra
}

// list element for *FlowExtra
type ElementFlowExtra struct {
	next, prev *ElementFlowExtra
	// The list to which this element belongs.
	list *ListFlowExtra
	// The value stored with this element.
	Value *FlowExtra
}

func (e *ElementFlowExtra) Next() *ElementFlowExtra {
	if p := e.next; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

func (e *ElementFlowExtra) Prev() *ElementFlowExtra {
	if p := e.prev; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

// list for *FlowExtra
type ListFlowExtra struct {
	root ElementFlowExtra
	len  int
}

func (l *ListFlowExtra) Init() *ListFlowExtra {
	l.root.next = &l.root
	l.root.prev = &l.root
	l.len = 0
	return l
}

func NewListFlowExtra() *ListFlowExtra { return new(ListFlowExtra).Init() }

func (l *ListFlowExtra) Len() int { return l.len }

func (l *ListFlowExtra) Front() *ElementFlowExtra {
	if l.len == 0 {
		return nil
	}
	return l.root.next
}

func (l *ListFlowExtra) Back() *ElementFlowExtra {
	if l.len == 0 {
		return nil
	}
	return l.root.prev
}

func (l *ListFlowExtra) lazyInit() {
	if l.root.next == nil {
		l.Init()
	}
}

func (l *ListFlowExtra) insert(e, at *ElementFlowExtra) *ElementFlowExtra {
	n := at.next
	at.next = e
	e.prev = at
	e.next = n
	n.prev = e
	e.list = l
	l.len++
	return e
}

func (l *ListFlowExtra) insertValue(v *FlowExtra, at *ElementFlowExtra) *ElementFlowExtra {
	return l.insert(&ElementFlowExtra{Value: v}, at)
}

func (l *ListFlowExtra) remove(e *ElementFlowExtra) *ElementFlowExtra {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // avoid memory leaks
	e.prev = nil // avoid memory leaks
	e.list = nil
	l.len--
	return e
}

func (l *ListFlowExtra) Remove(e *ElementFlowExtra) *FlowExtra {
	if e.list == l {
		l.remove(e)
	}
	return e.Value
}

func (l *ListFlowExtra) RemoveFront() *ElementFlowExtra {
	if l.root.next == nil {
		return nil
	}
	return l.remove(l.root.next)
}

func (l *ListFlowExtra) RemoveBack() *ElementFlowExtra {
	if l.root.prev == nil {
		return nil
	}
	return l.remove(l.root.next)
}

func (l *ListFlowExtra) PushFront(v *FlowExtra) *ElementFlowExtra {
	l.lazyInit()
	return l.insertValue(v, &l.root)
}

func (l *ListFlowExtra) PushBack(v *FlowExtra) *ElementFlowExtra {
	l.lazyInit()
	return l.insertValue(v, l.root.prev)
}

func (l *ListFlowExtra) MoveToFront(e *ElementFlowExtra) {
	if e.list != l || l.root.next == e {
		return
	}
	l.insert(l.remove(e), &l.root)
}

func (l *ListFlowExtra) MoveToBack(e *ElementFlowExtra) {
	if e.list != l || l.root.prev == e {
		return
	}
	l.insert(l.remove(e), l.root.prev)
}
