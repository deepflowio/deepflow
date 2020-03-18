package zerodoc

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type FlowSecondMeter struct {
	Traffic
	TCPFlowAnomaly
}

func (m *FlowSecondMeter) Reverse() {
	m.Traffic.Reverse()
	m.TCPFlowAnomaly.Reverse()
}

func (m *FlowSecondMeter) ID() uint8 {
	return FLOW_SECOND_ID
}

func (m *FlowSecondMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *FlowSecondMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *FlowSecondMeter) SortKey() uint64 {
	return m.PacketTx + m.PacketRx
}

func (m *FlowSecondMeter) Encode(encoder *codec.SimpleEncoder) {
	m.Traffic.Encode(encoder)
	m.TCPFlowAnomaly.Encode(encoder)
}

func (m *FlowSecondMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Traffic.Decode(decoder)
	m.TCPFlowAnomaly.Decode(decoder)
}

func (m *FlowSecondMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FlowSecondMeter); ok {
		m.Traffic.ConcurrentMerge(&pm.Traffic)
		m.TCPFlowAnomaly.ConcurrentMerge(&pm.TCPFlowAnomaly)
	}
}

func (m *FlowSecondMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*FlowSecondMeter); ok {
		m.Traffic.SequentialMerge(&pm.Traffic)
		m.TCPFlowAnomaly.SequentialMerge(&pm.TCPFlowAnomaly)
	}
}

func (m *FlowSecondMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *FlowSecondMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += m.Traffic.MarshalTo(b[offset:])
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

func (m *FlowSecondMeter) Fill(ids []uint8, values []interface{}) {
	for i, id := range ids {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		switch id {
		case _METER_PACKET_TX:
			m.PacketTx = uint64(values[i].(int64))
		case _METER_PACKET_RX:
			m.PacketRx = uint64(values[i].(int64))
		case _METER_BYTE_TX:
			m.ByteTx = uint64(values[i].(int64))
		case _METER_BYTE_RX:
			m.ByteRx = uint64(values[i].(int64))
		case _METER_FLOW:
			m.Flow = uint64(values[i].(int64))
		case _METER_NEW_FLOW:
			m.NewFlow = uint64(values[i].(int64))
		case _METER_CLOSED_FLOW:
			m.ClosedFlow = uint64(values[i].(int64))

		case _METER_CLIENT_RST_FLOW:
			m.ClientRstFlow = uint64(values[i].(int64))
		case _METER_SERVER_RST_FLOW:
			m.ServerRstFlow = uint64(values[i].(int64))
		case _METER_CLIENT_HALF_OPEN_FLOW:
			m.ClientHalfOpenFlow = uint64(values[i].(int64))
		case _METER_SERVER_HALF_OPEN_FLOW:
			m.ServerHalfOpenFlow = uint64(values[i].(int64))
		case _METER_CLIENT_HALF_CLOSE_FLOW:
			m.ClientHalfCloseFlow = uint64(values[i].(int64))
		case _METER_SERVER_HALF_CLOSE_FLOW:
			m.ServerHalfCloseFlow = uint64(values[i].(int64))
		case _METER_TIMEOUT_TCP_FLOW:
			m.TimeoutTCPFlow = uint64(values[i].(int64))
		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}

type FlowMeter struct {
	Traffic
	TCPLatency
	TCPPacketAnomaly
	TCPFlowAnomaly
}

func (m *FlowMeter) Reverse() {
	m.Traffic.Reverse()
	m.TCPLatency.Reverse()
	m.TCPPacketAnomaly.Reverse()
	m.TCPFlowAnomaly.Reverse()
}

func (m *FlowMeter) ID() uint8 {
	return FLOW_ID
}

func (m *FlowMeter) Name() string {
	return MeterVTAPNames[m.ID()]
}

func (m *FlowMeter) VTAPName() string {
	return MeterVTAPNames[m.ID()]
}

func (m *FlowMeter) SortKey() uint64 {
	return m.PacketTx + m.PacketRx
}

func (m *FlowMeter) Encode(encoder *codec.SimpleEncoder) {
	m.Traffic.Encode(encoder)
	m.TCPLatency.Encode(encoder)
	m.TCPPacketAnomaly.Encode(encoder)
	m.TCPFlowAnomaly.Encode(encoder)
}

func (m *FlowMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Traffic.Decode(decoder)
	m.TCPLatency.Decode(decoder)
	m.TCPPacketAnomaly.Decode(decoder)
	m.TCPFlowAnomaly.Decode(decoder)
}

func (m *FlowMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.Traffic.ConcurrentMerge(&pm.Traffic)
		m.TCPLatency.ConcurrentMerge(&pm.TCPLatency)
		m.TCPPacketAnomaly.ConcurrentMerge(&pm.TCPPacketAnomaly)
		m.TCPFlowAnomaly.ConcurrentMerge(&pm.TCPFlowAnomaly)
	}
}

func (m *FlowMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.Traffic.SequentialMerge(&pm.Traffic)
		m.TCPLatency.SequentialMerge(&pm.TCPLatency)
		m.TCPPacketAnomaly.SequentialMerge(&pm.TCPPacketAnomaly)
		m.TCPFlowAnomaly.SequentialMerge(&pm.TCPFlowAnomaly)
	}
}

func (m *FlowMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *FlowMeter) MarshalTo(b []byte) int {
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

func (m *FlowMeter) Fill(ids []uint8, values []interface{}) {
	for i, id := range ids {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		switch id {
		case _METER_PACKET_TX:
			m.PacketTx = uint64(values[i].(int64))
		case _METER_PACKET_RX:
			m.PacketRx = uint64(values[i].(int64))
		case _METER_BYTE_TX:
			m.ByteTx = uint64(values[i].(int64))
		case _METER_BYTE_RX:
			m.ByteRx = uint64(values[i].(int64))
		case _METER_FLOW:
			m.Flow = uint64(values[i].(int64))
		case _METER_NEW_FLOW:
			m.NewFlow = uint64(values[i].(int64))
		case _METER_CLOSED_FLOW:
			m.ClosedFlow = uint64(values[i].(int64))

		case _METER_RTT_SUM:
			m.RTTSum = time.Duration(values[i].(int64))
		case _METER_RTT_CLIENT_SUM:
			m.RTTClientSum = time.Duration(values[i].(int64))
		case _METER_RTT_SERVER_SUM:
			m.RTTServerSum = time.Duration(values[i].(int64))
		case _METER_SRT_SUM:
			m.SRTSum = time.Duration(values[i].(int64))
		case _METER_ART_SUM:
			m.ARTSum = time.Duration(values[i].(int64))
		case _METER_RTT_COUNT:
			m.RTTCount = uint64(values[i].(int64))
		case _METER_RTT_CLIENT_COUNT:
			m.RTTClientCount = uint64(values[i].(int64))
		case _METER_RTT_SERVER_COUNT:
			m.RTTServerCount = uint64(values[i].(int64))
		case _METER_SRT_COUNT:
			m.SRTCount = uint64(values[i].(int64))
		case _METER_ART_COUNT:
			m.ARTCount = uint64(values[i].(int64))

		case _METER_RETRANS_TX:
			m.RetransTx = uint64(values[i].(int64))
		case _METER_RETRANS_RX:
			m.RetransRx = uint64(values[i].(int64))
		case _METER_ZERO_WIN_TX:
			m.ZeroWinTx = uint64(values[i].(int64))
		case _METER_ZERO_WIN_RX:
			m.ZeroWinRx = uint64(values[i].(int64))

		case _METER_CLIENT_RST_FLOW:
			m.ClientRstFlow = uint64(values[i].(int64))
		case _METER_SERVER_RST_FLOW:
			m.ServerRstFlow = uint64(values[i].(int64))
		case _METER_CLIENT_HALF_OPEN_FLOW:
			m.ClientHalfOpenFlow = uint64(values[i].(int64))
		case _METER_SERVER_HALF_OPEN_FLOW:
			m.ServerHalfOpenFlow = uint64(values[i].(int64))
		case _METER_CLIENT_HALF_CLOSE_FLOW:
			m.ClientHalfCloseFlow = uint64(values[i].(int64))
		case _METER_SERVER_HALF_CLOSE_FLOW:
			m.ServerHalfCloseFlow = uint64(values[i].(int64))
		case _METER_TIMEOUT_TCP_FLOW:
			m.TimeoutTCPFlow = uint64(values[i].(int64))

		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}
