package flowgenerator

import (
	"time"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/pool"
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
	taggedFlow    *TaggedFlow
	metaFlowPerf  *MetaFlowPerf
	minArrTime    time.Duration
	recentTime    time.Duration
	timeout       time.Duration
	flowState     FlowState
	reported      bool
	reversed      bool
	circlePktGot  bool
	hasFlowAction bool
}

var flowExtraPool = pool.NewLockFreePool(func() interface{} {
	return new(FlowExtra)
})

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

// list element for *FlowExtra
type ElementFlowExtra struct {
	next, prev *ElementFlowExtra
	// The list to which this element belongs.
	list *ListFlowExtra
	// The value stored with this element.
	Value *FlowExtra
}

var elementFlowExtraPool = pool.NewLockFreePool(func() interface{} {
	return new(ElementFlowExtra)
})

func AcquireElementFlowExtra() *ElementFlowExtra {
	return elementFlowExtraPool.Get().(*ElementFlowExtra)
}

func ReleaseElementFlowExtra(efe *ElementFlowExtra) {
	*efe = ElementFlowExtra{}
	elementFlowExtraPool.Put(efe)
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
	efe := AcquireElementFlowExtra()
	efe.Value = v
	return l.insert(efe, at)
}

func (l *ListFlowExtra) remove(e *ElementFlowExtra) {
	e.prev.next = e.next
	e.next.prev = e.prev
	l.len--
	ReleaseElementFlowExtra(e) // 所有e的成员指针将会被清空为nil
}

func (l *ListFlowExtra) Remove(e *ElementFlowExtra) {
	if e.list == l {
		l.remove(e)
	}
}

func (l *ListFlowExtra) PushFront(v *FlowExtra) *ElementFlowExtra {
	l.lazyInit()
	return l.insertValue(v, &l.root)
}
