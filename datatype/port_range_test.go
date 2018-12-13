package datatype

import (
	"reflect"
	"testing"
)

func TestPortRange(t *testing.T) {
	expect := []PortRange{NewPortRange(1, 1), NewPortRange(2, 2), NewPortRange(3, 3)}
	result := GetPortRanges([]PortRange{NewPortRange(1, 2), NewPortRange(2, 3)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 1), NewPortRange(2, 2)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 2), NewPortRange(2, 2)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 1), NewPortRange(2, 2)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 1), NewPortRange(1, 2)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 1), NewPortRange(2, 2)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 1), NewPortRange(2, 2)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 4), NewPortRange(5, 8), NewPortRange(9, 10)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 10), NewPortRange(5, 8)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 8), NewPortRange(9, 9), NewPortRange(10, 10), NewPortRange(11, 15), NewPortRange(16, 20)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 10), NewPortRange(9, 15), NewPortRange(10, 20)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}

	expect = []PortRange{NewPortRange(1, 8), NewPortRange(9, 9), NewPortRange(10, 10), NewPortRange(11, 15), NewPortRange(16, 18), NewPortRange(19, 20)}
	result = GetPortRanges([]PortRange{NewPortRange(1, 10), NewPortRange(9, 15), NewPortRange(10, 20), NewPortRange(11, 18)})
	if !reflect.DeepEqual(expect, result) {
		t.Errorf("TestPortRange expect: %+v  return: %+v ", expect, result)
	}
}
