package datastructure

import (
	"sync"
)

const ELEMENT_POOL_BLOCK_SIZE = 65536

type Element struct {
	Value interface{}
	Next  *Element
}

func WrapElement(v interface{}) *Element {
	e := elementPool.Get()
	e.Value = v
	return e
}

func UnwrapElement(e *Element) interface{} {
	v := e.Value
	elementPool.Put(e)
	return v
}

type ElementPool sync.Pool

func makeElementBlock() []*Element {
	block := make([]Element, ELEMENT_POOL_BLOCK_SIZE)
	slice := make([]*Element, ELEMENT_POOL_BLOCK_SIZE)
	for i, _ := range block {
		slice[i] = &block[i]
	}
	return slice
}

func (p *ElementPool) Get() *Element {
	pElements := (*sync.Pool)(p).Get().(*[]*Element) // avoid convT2Eslice
	elements := *pElements
	if len(elements) == 1 {
		*pElements = makeElementBlock()
	} else {
		*pElements = elements[:len(elements)-1]
	}
	(*sync.Pool)(p).Put(pElements)
	return elements[len(elements)-1]
}

func (p *ElementPool) Put(x *Element) {
	*x = Element{}
	pElements := (*sync.Pool)(p).Get().(*[]*Element) // avoid convT2Eslice
	if len(*pElements) < cap(*pElements) {
		*pElements = append(*pElements, x)
	}
	(*sync.Pool)(p).Put(pElements)
}

func NewElementPool() ElementPool {
	return ElementPool{
		New: func() interface{} {
			slice := makeElementBlock()
			return &slice
		},
	}
}

var elementPool = NewElementPool()
