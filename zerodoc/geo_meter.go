package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type GeoMeter struct {
	Traffic
	TCPLatency
	TCPPacketAnomaly
	TCPFlowAnomaly
}

func (m *GeoMeter) Reverse() {
	m.Traffic.Reverse()
	m.TCPLatency.Reverse()
	m.TCPPacketAnomaly.Reverse()
	m.TCPFlowAnomaly.Reverse()
}

func (m *GeoMeter) ID() uint8 {
	return GEO_ID
}

func (m *GeoMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *GeoMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *GeoMeter) SortKey() uint64 {
	return m.PacketTx + m.PacketRx
}

func (m *GeoMeter) Encode(encoder *codec.SimpleEncoder) {
	m.Traffic.Encode(encoder)
	m.TCPLatency.Encode(encoder)
	m.TCPPacketAnomaly.Encode(encoder)
	m.TCPFlowAnomaly.Encode(encoder)
}

func (m *GeoMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Traffic.Decode(decoder)
	m.TCPLatency.Decode(decoder)
	m.TCPPacketAnomaly.Decode(decoder)
	m.TCPFlowAnomaly.Decode(decoder)
}

func (m *GeoMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*GeoMeter); ok {
		m.Traffic.ConcurrentMerge(&pm.Traffic)
		m.TCPLatency.ConcurrentMerge(&pm.TCPLatency)
		m.TCPPacketAnomaly.ConcurrentMerge(&pm.TCPPacketAnomaly)
		m.TCPFlowAnomaly.ConcurrentMerge(&pm.TCPFlowAnomaly)
	}
}

func (m *GeoMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*GeoMeter); ok {
		m.Traffic.SequentialMerge(&pm.Traffic)
		m.TCPLatency.SequentialMerge(&pm.TCPLatency)
		m.TCPPacketAnomaly.SequentialMerge(&pm.TCPPacketAnomaly)
		m.TCPFlowAnomaly.SequentialMerge(&pm.TCPFlowAnomaly)
	}
}

func (m *GeoMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *GeoMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += m.Traffic.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.TCPLatency.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.TCPPacketAnomaly.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.TCPFlowAnomaly.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] == ',' {
		offset--
	}

	return offset
}

func (m *GeoMeter) Fill(ids []uint8, values []interface{}) {
	for i, id := range ids {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		v, ok := values[i].(int64)
		if !ok {
			continue
		}
		switch id {
		case _METER_PACKET_TX:
			m.PacketTx = uint64(v)
		case _METER_PACKET_RX:
			m.PacketRx = uint64(v)
		case _METER_BYTE_TX:
			m.ByteTx = uint64(v)
		case _METER_BYTE_RX:
			m.ByteRx = uint64(v)
		case _METER_FLOW:
			m.Flow = uint64(v)
		case _METER_NEW_FLOW:
			m.NewFlow = uint64(v)
		case _METER_CLOSED_FLOW:
			m.ClosedFlow = uint64(v)

		case _METER_RTT:
			m.RTTSum = uint64(v)
			m.RTTCount = 1
		case _METER_RTT_CLIENT:
			m.RTTClientSum = uint64(v)
			m.RTTClientCount = 1
		case _METER_RTT_SERVER:
			m.RTTServerSum = uint64(v)
			m.RTTServerCount = 1
		case _METER_SRT:
			m.SRTSum = uint64(v)
			m.SRTCount = 1
		case _METER_ART:
			m.ARTSum = uint64(v)
			m.ARTCount = 1

		case _METER_RETRANS_TX:
			m.RetransTx = uint64(v)
		case _METER_RETRANS_RX:
			m.RetransRx = uint64(v)
		case _METER_ZERO_WIN_TX:
			m.ZeroWinTx = uint64(v)
		case _METER_ZERO_WIN_RX:
			m.ZeroWinRx = uint64(v)

		case _METER_CLIENT_RST_FLOW:
			m.ClientRstFlow = uint64(v)
		case _METER_SERVER_RST_FLOW:
			m.ServerRstFlow = uint64(v)
		case _METER_CLIENT_HALF_OPEN_FLOW:
			m.ClientHalfOpenFlow = uint64(v)
		case _METER_SERVER_HALF_OPEN_FLOW:
			m.ServerHalfOpenFlow = uint64(v)
		case _METER_CLIENT_HALF_CLOSE_FLOW:
			m.ClientHalfCloseFlow = uint64(v)
		case _METER_SERVER_HALF_CLOSE_FLOW:
			m.ServerHalfCloseFlow = uint64(v)
		case _METER_TIMEOUT_TCP_FLOW:
			m.TimeoutTCPFlow = uint64(v)

		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}
