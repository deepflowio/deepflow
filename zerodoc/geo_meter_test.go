package zerodoc

import (
	"testing"
)

func TestMarshalGeoMeter(t *testing.T) {
	var buffer [1024]byte
	var l int

	m1 := GeoMeter{
		Traffic: Traffic{
			PacketTx:   1,
			PacketRx:   2,
			ByteTx:     3,
			ByteRx:     4,
			Flow:       5,
			NewFlow:    6,
			ClosedFlow: 7,
		},
	}
	l = m1.MarshalTo(buffer[:])
	if string(buffer[:l]) != "byte_tx=3i,packet_tx=1i,packet_rx=2i,byte_rx=4i,flow=5i,new_flow=6i,closed_flow=7i" {
		t.Error("MarshalTo()实现不正确")
	}

	m2 := GeoMeter{
		Latency: Latency{
			RTTClientSum:   uint64(1000),
			RTTClientCount: 2,
		},
	}
	l = m2.MarshalTo(buffer[:])
	if string(buffer[:l]) != "byte_tx=0i,rtt_client=500i" {
		t.Error("MarshalTo()实现不正确")
	}

	m3 := GeoMeter{
		Traffic: Traffic{
			PacketTx:   1,
			PacketRx:   2,
			ByteTx:     3,
			ByteRx:     4,
			Flow:       5,
			NewFlow:    6,
			ClosedFlow: 7,
		},
		Anomaly: Anomaly{
			ClientRstFlow:      1,
			ServerSYNACKRepeat: 1,
		},
	}
	l = m3.MarshalTo(buffer[:])
	if string(buffer[:l]) != "byte_tx=3i,packet_tx=1i,packet_rx=2i,byte_rx=4i,flow=5i,new_flow=6i,closed_flow=7i,client_rst_flow=1i,server_syn_ack_repeat=1i" {
		t.Error("MarshalTo()实现不正确")
	}
}
