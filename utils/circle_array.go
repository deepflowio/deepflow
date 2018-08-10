package utils

import (
	"errors"
)

var OutOfCapacity = errors.New("Out of capacity")

type Value = interface{}

type CircleArray struct {
	items  []Value
	first  int
	length int
}

func (a *CircleArray) Len() int {
	return a.length
}

func (a *CircleArray) Get(index int) Value {
	if index >= a.length {
		panic("Index out of range")
	}
	return a.items[(a.first+index)%len(a.items)]
}

func (a *CircleArray) Put(index int, v Value) {
	if index >= a.length {
		panic("Index out of range")
	}
	a.items[(a.first+index)%len(a.items)] = v
}

func (a *CircleArray) Append(v Value) error {
	if a.length >= len(a.items) {
		return OutOfCapacity
	}
	a.items[(a.first+a.length)%len(a.items)] = v
	a.length++
	return nil
}

func (a *CircleArray) Push(v Value) { // will overwrite
	a.items[(a.first+a.length)%len(a.items)] = v
	a.length++
	if a.length > len(a.items) {
		a.length = len(a.items)
		a.first++
	}
}

func (a *CircleArray) Pop() Value {
	if a.length <= 0 {
		return nil
	}
	v := a.items[a.first]
	a.length--
	a.first = (a.first + 1) % len(a.items)
	return v
}

func (a *CircleArray) Resize(size int) {
	items := make([]Value, size)
	copy(items, a.items)
	a.items = items
}

func (a *CircleArray) Init(size int) {
	a.items = make([]Value, size)
}
