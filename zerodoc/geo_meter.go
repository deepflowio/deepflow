package zerodoc

import (
	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type GeoMeter struct {
	Traffic
	Latency
	Performance
	Anomaly
}

func (m *GeoMeter) Reverse() {
	m.Traffic.Reverse()
	m.Latency.Reverse()
	m.Performance.Reverse()
	m.Anomaly.Reverse()
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
	m.Latency.Encode(encoder)
	m.Performance.Encode(encoder)
	m.Anomaly.Encode(encoder)
}

func (m *GeoMeter) Decode(decoder *codec.SimpleDecoder) {
	m.Traffic.Decode(decoder)
	m.Latency.Decode(decoder)
	m.Performance.Decode(decoder)
	m.Anomaly.Decode(decoder)
}

func (m *GeoMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*GeoMeter); ok {
		m.Traffic.ConcurrentMerge(&pm.Traffic)
		m.Latency.ConcurrentMerge(&pm.Latency)
		m.Performance.ConcurrentMerge(&pm.Performance)
		m.Anomaly.ConcurrentMerge(&pm.Anomaly)
	}
}

func (m *GeoMeter) SequentialMerge(other app.Meter) {
	if pm, ok := other.(*GeoMeter); ok {
		m.Traffic.SequentialMerge(&pm.Traffic)
		m.Latency.SequentialMerge(&pm.Latency)
		m.Performance.SequentialMerge(&pm.Performance)
		m.Anomaly.SequentialMerge(&pm.Anomaly)
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
	if offset > 0 && b[offset-1] == ',' {
		offset--
	}

	return offset
}
