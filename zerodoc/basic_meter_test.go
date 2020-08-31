package zerodoc

import (
	"reflect"
	"testing"
)

func TestMarshalTraffic(t *testing.T) {
	var buffer [1024]byte
	var l int

	t1 := Traffic{
		PacketTx:     1,
		PacketRx:     2,
		ByteTx:       3,
		ByteRx:       4,
		L3ByteTx:     12,
		L3ByteRx:     13,
		Flow:         5,
		NewFlow:      6,
		ClosedFlow:   7,
		HTTPRequest:  8,
		HTTPResponse: 9,
		DNSRequest:   10,
		DNSResponse:  11,
	}
	l = t1.MarshalTo(buffer[:])
	if string(buffer[:l]) != "packet=3i,packet_tx=1i,packet_rx=2i,byte_tx=3i,byte_rx=4i,byte=7i,l3_byte_tx=12i,l3_byte_rx=13i,flow=5i,new_flow=6i,closed_flow=7i"+
		",http_request=8i,http_response=9i,dns_request=10i,dns_response=11i" {
		t.Error("MarshalTo()实现不正确")
	}

	t2 := Traffic{
		ByteTx:  3,
		NewFlow: 4,
	}
	l = t2.MarshalTo(buffer[:])
	if string(buffer[:l]) != "packet=0i,byte_tx=3i,byte=3i,new_flow=4i" {
		t.Error("MarshalTo()实现不正确")
	}
}

func TestReverse(t *testing.T) {
	t1 := Traffic{
		PacketTx:     1,
		PacketRx:     2,
		ByteTx:       3,
		ByteRx:       4,
		Flow:         5,
		NewFlow:      6,
		ClosedFlow:   7,
		HTTPRequest:  8,
		HTTPResponse: 9,
		DNSRequest:   10,
		DNSResponse:  11,
		L3ByteTx:     12,
		L3ByteRx:     13,
	}
	t2 := Traffic{
		PacketTx:     2,
		PacketRx:     1,
		ByteTx:       4,
		ByteRx:       3,
		Flow:         5,
		NewFlow:      6,
		ClosedFlow:   7,
		HTTPRequest:  8,
		HTTPResponse: 9,
		DNSRequest:   10,
		DNSResponse:  11,
		L3ByteTx:     13,
		L3ByteRx:     12,
	}

	t1.Reverse()
	if t1 != t2 {
		t.Error("Reverse()实现不正确")
	}
}

func initMeter(m interface{}, n uint64) {
	v := reflect.ValueOf(m)
	if v.IsNil() {
		return
	}

	v = reflect.Indirect(v)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Uint64:
			f.SetUint(n)
		default:
			continue
		}
	}
}

func TestMerge(t *testing.T) {
	t1, t2 := &Traffic{}, &Traffic{}
	initMeter(t1, 1)
	initMeter(t2, 2)
	t.Log(t1)
	t1.ConcurrentMerge(t1)
	if *t1 != *t2 {
		t.Errorf("Traffic ConcurrentMerge failed, expected:%v, actual:%v", t2, t1)
	}

	l1, l2 := &Latency{}, &Latency{}
	initMeter(l1, 1)
	initMeter(l2, 2)
	l1.ConcurrentMerge(l1)
	if *l1 != *l2 {
		t.Errorf("Latency ConcurrentMerge failed, expected:%v, actual:%v", l2, l1)
	}

	p1, p2 := &Performance{}, &Performance{}
	initMeter(p1, 1)
	initMeter(p2, 2)
	p1.ConcurrentMerge(p1)
	if *p1 != *p2 {
		t.Errorf("Performance ConcurrentMerge failed, expected:%v, actual:%v", p2, p1)
	}

	a1, a2 := &Anomaly{}, &Anomaly{}
	initMeter(a1, 1)
	initMeter(a2, 2)
	a1.ConcurrentMerge(a1)
	if *a1 != *a2 {
		t.Errorf("Anomaly ConcurrentMerge failed, expected:%v, actual:%v", a2, a1)
	}
}
