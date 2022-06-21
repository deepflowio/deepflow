package segmenttree

import (
	"errors"
)

var (
	InvalidDimension           = errors.New("Invalid dimension")
	InsufficientIntervalLength = errors.New("Insufficient interval length")
)

type Endpoint = int64

type Interval interface {
	Lower() (Endpoint, bool)
	Upper() (Endpoint, bool)
}

type Value interface {
	Id() uint64 // unique number for identification
}

type Intervals = []Interval

type Entry struct {
	Intervals Intervals
	Value     Value
}

type Tree interface {
	Query(...Interval) []Value
}
