package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/app"
	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type FPSMeter struct {
	SumFlowCount       uint64 `db:"sum_flow_count"`
	SumNewFlowCount    uint64 `db:"sum_new_flow_count"`
	SumClosedFlowCount uint64 `db:"sum_closed_flow_count"`
}

func (m *FPSMeter) ID() uint8 {
	return FPS_ID
}

func (m *FPSMeter) Name() string {
	return MeterDFNames[FPS_ID]
}

func (m *FPSMeter) VTAPName() string {
	return MeterVTAPNames[FPS_ID]
}

func (m *FPSMeter) SortKey() uint64 {
	return m.SumFlowCount
}

func (m *FPSMeter) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(m.SumFlowCount)
	encoder.WriteVarintU64(m.SumNewFlowCount)
	encoder.WriteVarintU64(m.SumClosedFlowCount)
}

func (m *FPSMeter) Decode(decoder *codec.SimpleDecoder) {
	m.SumFlowCount = decoder.ReadVarintU64()
	m.SumNewFlowCount = decoder.ReadVarintU64()
	m.SumClosedFlowCount = decoder.ReadVarintU64()
}

func (m *FPSMeter) ConcurrentMerge(other app.Meter) {
	if pm, ok := other.(*FPSMeter); ok {
		m.SumFlowCount += pm.SumFlowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount
	}
}

// 秒级SumFlowCount计算方法：
//
// 在统计每秒流数量时，为了降低压力，仅对新建和结束的时刻做统计：
//   设原始数据中当前秒的流数量、新建流数量、结束流数量分别是F1, N1, C1
//   设原始数据中下一秒的流数量、新建流数量、结束流数量分别为F2, N2, C2
//
// 当前秒未结束的流数量: F1 - C1
//
// 于是下一秒矫正的统计量为：
//   流数量: F2' = MAX( (F1-C1)+N2, F2 )	// 若中间有数据丢失，F1偏小需要矫正
//   未结束的流数量: F2' - C2
//   新建流数量: N2
//   结束流数量: C2
//
// 于是当前秒和下一秒的合并统计量为：
//   累积流数量：C1 + F2'			// 不要使用F1 + N2，因为F1可能偏小
//   累积新建流数量: N1 + N2
//   累积结束流数量: C1 + C2
//   未结束的流数量: F2' - C2 = (C1 + F2') - (C1 + C2)	// 即可以使用累积量相减
func (m *FPSMeter) SequentialMerge(other app.Meter) { // other为下一秒的统计量
	if pm, ok := other.(*FPSMeter); ok {
		// 当前秒未结束的流数量
		notClosedFlowCount := uint64(0)
		if m.SumFlowCount > m.SumClosedFlowCount {
			notClosedFlowCount = m.SumFlowCount - m.SumClosedFlowCount
		}
		// 下一秒矫正后的流数量
		flowCount := maxU64(notClosedFlowCount+pm.SumNewFlowCount, pm.SumFlowCount)
		// 累积统计量
		m.SumFlowCount = m.SumClosedFlowCount + flowCount
		m.SumNewFlowCount += pm.SumNewFlowCount
		m.SumClosedFlowCount += pm.SumClosedFlowCount
	}
}

func (m *FPSMeter) ToKVString() string {
	buffer := make([]byte, MAX_STRING_LENGTH)
	size := m.MarshalTo(buffer)
	return string(buffer[:size])
}

func (m *FPSMeter) MarshalTo(b []byte) int {
	offset := 0

	offset += copy(b[offset:], "sum_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumFlowCount, 10))
	offset += copy(b[offset:], "i,sum_new_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumNewFlowCount, 10))
	offset += copy(b[offset:], "i,sum_closed_flow_count=")
	offset += copy(b[offset:], strconv.FormatUint(m.SumClosedFlowCount, 10))
	b[offset] = 'i'
	offset++

	return offset
}

func (m *FPSMeter) Fill(ids []uint8, values []interface{}) {
	for i, id := range ids {
		if id <= _METER_INVALID_ || id >= _METER_MAX_ID_ || values[i] == nil {
			continue
		}
		switch id {
		case _METER_SUM_FLOW_COUNT:
			m.SumFlowCount = uint64(values[i].(int64))
		case _METER_SUM_NEW_FLOW_COUNT:
			m.SumNewFlowCount = uint64(values[i].(int64))
		case _METER_SUM_CLOSED_FLOW_COUNT:
			m.SumClosedFlowCount = uint64(values[i].(int64))
		default:
			log.Warningf("unsupport meter id=%d", id)
		}
	}
}
