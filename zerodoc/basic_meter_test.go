package zerodoc

import "testing"

func TestMarshalTraffic(t *testing.T) {
	var buffer [1024]byte
	var l int

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
	}
	l = t1.MarshalTo(buffer[:])
	if string(buffer[:l]) != "packet_tx=1i,packet_rx=2i,byte_tx=3i,byte_rx=4i,flow=5i,new_flow=6i,closed_flow=7i"+
		",http_request=8i,http_response=9i,dns_request=10i,dns_response=11i" {
		t.Error("MarshalTo()实现不正确")
	}

	t2 := Traffic{
		ByteTx:  3,
		NewFlow: 4,
	}
	l = t2.MarshalTo(buffer[:])
	if string(buffer[:l]) != "byte_tx=3i,new_flow=4i" {
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
	}

	t1.Reverse()
	if t1 != t2 {
		t.Error("Reverse()实现不正确")
	}
}
