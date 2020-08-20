package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type FlowMeter struct {
	Traffic
	Latency
	Performance
	Anomaly
	FlowLoad
}

func (m *FlowMeter) Reverse() {
	m.Traffic.Reverse()
	m.Latency.Reverse()
	m.Performance.Reverse()
	m.Anomaly.Reverse()
	m.FlowLoad.Reverse()
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
	m.Latency.Encode(encoder)
	m.Performance.Encode(encoder)
	m.Anomaly.Encode(encoder)
	m.FlowLoad.Encode(encoder)
}

func (m *FlowMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Traffic.Decode(decoder)
	m.Latency.Decode(decoder)
	m.Performance.Decode(decoder)
	m.Anomaly.Decode(decoder)
	m.FlowLoad.Decode(decoder)
}

func (m *FlowMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.Traffic.ConcurrentMerge(&pm.Traffic)
		m.Latency.ConcurrentMerge(&pm.Latency)
		m.Performance.ConcurrentMerge(&pm.Performance)
		m.Anomaly.ConcurrentMerge(&pm.Anomaly)
		m.FlowLoad.ConcurrentMerge(&pm.FlowLoad)
	}
}

func (m *FlowMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*FlowMeter); ok {
		m.Traffic.SequentialMerge(&pm.Traffic)
		m.Latency.SequentialMerge(&pm.Latency)
		m.Performance.SequentialMerge(&pm.Performance)
		m.Anomaly.SequentialMerge(&pm.Anomaly)
		m.FlowLoad.SequentialMerge(&pm.FlowLoad)
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
	offset += m.Latency.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.Performance.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.Anomaly.MarshalTo(b[offset:])
	if offset > 0 && b[offset-1] != ',' {
		b[offset] = ','
		offset++
	}
	offset += m.FlowLoad.MarshalTo(b[offset:])
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
		case _METER_L3_BYTE_TX:
			m.L3ByteTx = uint64(v)
		case _METER_L3_BYTE_RX:
			m.L3ByteRx = uint64(v)
		case _METER_FLOW:
			m.Flow = uint64(v)
		case _METER_NEW_FLOW:
			m.NewFlow = uint64(v)
		case _METER_CLOSED_FLOW:
			m.ClosedFlow = uint64(v)
		case _METER_HTTP_REQUEST:
			m.HTTPRequest = uint64(v)
		case _METER_HTTP_RESPONSE:
			m.HTTPResponse = uint64(v)
		case _METER_DNS_REQUEST:
			m.DNSRequest = uint64(v)
		case _METER_DNS_RESPONSE:
			m.DNSResponse = uint64(v)

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
		case _METER_HTTP_RRT:
			m.HTTPRRTSum = uint64(v)
			m.HTTPRRTCount = 1
		case _METER_DNS_RRT:
			m.DNSRRTSum = uint64(v)
			m.DNSRRTCount = 1

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
		case _METER_SERVER_SYN_ACK_REPEAT:
			m.ServerSYNACKRepeat = uint64(v)
		case _METER_CLIENT_SYN_REPEAT:
			m.ClientSynRepeat = uint64(v)
		case _METER_CLIENT_HALF_CLOSE_FLOW:
			m.ClientHalfCloseFlow = uint64(v)
		case _METER_SERVER_HALF_CLOSE_FLOW:
			m.ServerHalfCloseFlow = uint64(v)

		case _METER_CLIENT_NO_RESPONSE:
			m.ClientNoResponse = uint64(v)
		case _METER_CLIENT_SOURCE_PORT_REUSE:
			m.ClientSourcePortReuse = uint64(v)
		case _METER_CLIENT_SYN_RETRY_LACK:
			m.ClientSYNRetryLack = uint64(v)
		case _METER_SERVER_RESET:
			m.ServerReset = uint64(v)
		case _METER_SERVER_NO_RESPONSE:
			m.ServerNoResponse = uint64(v)
		case _METER_SERVER_QUEUE_LACK:
			m.ServerQueueLack = uint64(v)

		case _METER_HTTP_CLIENT_ERROR:
			m.HTTPClientError = uint64(v)
		case _METER_HTTP_SERVER_ERROR:
			m.HTTPServerError = uint64(v)
		case _METER_DNS_CLIENT_ERROR:
			m.DNSClientError = uint64(v)
		case _METER_DNS_SERVER_ERROR:
			m.DNSServerError = uint64(v)

		case _METER_FLOW_LOAD_MAX:
			m.Max = uint64(v)
		case _METER_FLOW_LOAD_MIN:
			m.Min = uint64(v)

		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}
