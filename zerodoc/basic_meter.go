package zerodoc

import (
	"strconv"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type Traffic struct {
	PacketTx   uint64 `db:"packet_tx"`
	PacketRx   uint64 `db:"packet_rx"`
	ByteTx     uint64 `db:"byte_tx"`
	ByteRx     uint64 `db:"byte_rx"`
	Flow       uint64 `db:"flow"`
	NewFlow    uint64 `db:"new_flow"`
	ClosedFlow uint64 `db:"closed_flow"`
}

func (t *Traffic) Reverse() {
	t.PacketTx, t.PacketRx = t.PacketRx, t.PacketTx
	t.ByteTx, t.ByteRx = t.ByteRx, t.ByteTx
}

func (t *Traffic) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(t.PacketTx)
	encoder.WriteVarintU64(t.PacketRx)
	encoder.WriteVarintU64(t.ByteTx)
	encoder.WriteVarintU64(t.ByteRx)
	encoder.WriteVarintU64(t.Flow)
	encoder.WriteVarintU64(t.NewFlow)
	encoder.WriteVarintU64(t.ClosedFlow)
}

func (t *Traffic) Decode(decoder *codec.SimpleDecoder) {
	t.PacketTx = decoder.ReadVarintU64()
	t.PacketRx = decoder.ReadVarintU64()
	t.ByteTx = decoder.ReadVarintU64()
	t.ByteRx = decoder.ReadVarintU64()
	t.Flow = decoder.ReadVarintU64()
	t.NewFlow = decoder.ReadVarintU64()
	t.ClosedFlow = decoder.ReadVarintU64()
}

func (t *Traffic) ConcurrentMerge(other *Traffic) {
	t.PacketTx += other.PacketTx
	t.PacketRx += other.PacketRx
	t.ByteTx += other.ByteTx
	t.ByteRx += other.ByteRx
	t.Flow += other.Flow
	t.NewFlow += other.NewFlow
	t.ClosedFlow += other.ClosedFlow
}

func (t *Traffic) SequentialMerge(other *Traffic) {
	t.PacketTx += other.PacketTx
	t.PacketRx += other.PacketRx
	t.ByteTx += other.ByteTx
	t.ByteRx += other.ByteRx
	t.Flow = t.ClosedFlow + other.Flow
	t.NewFlow += other.NewFlow
	t.ClosedFlow += other.ClosedFlow
}

func (t *Traffic) MarshalTo(b []byte) int {
	fields := []string{
		"packet_tx=", "packet_rx=", "byte_tx=", "byte_rx=", "flow=", "new_flow=", "closed_flow=",
	}
	values := []uint64{
		t.PacketTx, t.PacketRx, t.ByteTx, t.ByteRx, t.Flow, t.NewFlow, t.ClosedFlow,
	}
	return marshalKeyValues(b, fields, values)
}

type TCPLatency struct {
	RTTSum         time.Duration `db:"rtt_sum"`
	RTTClientSum   time.Duration `db:"rtt_client_sum"`
	RTTServerSum   time.Duration `db:"rtt_server_sum"`
	SRTSum         time.Duration `db:"srt_sum"`
	ARTSum         time.Duration `db:"art_sum"`
	RTTCount       uint64        `db:"rtt_count"`
	RTTClientCount uint64        `db:"rtt_client_count"`
	RTTServerCount uint64        `db:"rtt_server_count"`
	SRTCount       uint64        `db:"srt_count"`
	ARTCount       uint64        `db:"art_count"`
}

func (_ *TCPLatency) Reverse() {
}

func (l *TCPLatency) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(uint64(l.RTTSum))
	encoder.WriteVarintU64(uint64(l.RTTClientSum))
	encoder.WriteVarintU64(uint64(l.RTTServerSum))
	encoder.WriteVarintU64(uint64(l.SRTSum))
	encoder.WriteVarintU64(uint64(l.ARTSum))
	encoder.WriteVarintU64(l.RTTCount)
	encoder.WriteVarintU64(l.RTTClientCount)
	encoder.WriteVarintU64(l.RTTServerCount)
	encoder.WriteVarintU64(l.SRTCount)
	encoder.WriteVarintU64(l.ARTCount)
}

func (l *TCPLatency) Decode(decoder *codec.SimpleDecoder) {
	l.RTTSum = time.Duration(decoder.ReadVarintU64())
	l.RTTClientSum = time.Duration(decoder.ReadVarintU64())
	l.RTTServerSum = time.Duration(decoder.ReadVarintU64())
	l.SRTSum = time.Duration(decoder.ReadVarintU64())
	l.ARTSum = time.Duration(decoder.ReadVarintU64())
	l.RTTCount = decoder.ReadVarintU64()
	l.RTTClientCount = decoder.ReadVarintU64()
	l.RTTServerCount = decoder.ReadVarintU64()
	l.SRTCount = decoder.ReadVarintU64()
	l.ARTCount = decoder.ReadVarintU64()
}

func (l *TCPLatency) ConcurrentMerge(other *TCPLatency) {
	l.RTTSum += other.RTTSum
	l.RTTClientSum += other.RTTClientSum
	l.RTTServerSum += other.RTTServerSum
	l.SRTSum += other.SRTSum
	l.ARTSum += other.ARTSum
	l.RTTCount += other.RTTCount
	l.RTTClientCount += other.RTTClientCount
	l.RTTServerCount += other.RTTServerCount
	l.SRTCount += other.SRTCount
	l.ARTCount += other.ARTCount
}

func (l *TCPLatency) SequentialMerge(other *TCPLatency) {
	l.ConcurrentMerge(other)
}

func (l *TCPLatency) MarshalTo(b []byte) int {
	fields := []string{
		"rtt_sum=", "rtt_client_sum=", "rtt_server_sum=", "srt_sum=", "art_sum=",
		"rtt_count=", "rtt_client_count=", "rtt_server_count=", "srt_count=", "art_count=",
	}
	values := []uint64{
		uint64(l.RTTSum / time.Microsecond),
		uint64(l.RTTClientSum / time.Microsecond),
		uint64(l.RTTServerSum / time.Microsecond),
		uint64(l.SRTSum / time.Microsecond),
		uint64(l.ARTSum / time.Microsecond),
		l.RTTCount, l.RTTClientCount, l.RTTServerCount, l.SRTCount, l.ARTCount,
	}
	return marshalKeyValues(b, fields, values)
}

type TCPPacketAnomaly struct {
	RetransTx uint64 `db:"retrans_tx"`
	RetransRx uint64 `db:"retrans_rx"`
	ZeroWinTx uint64 `db:"zero_win_tx"`
	ZeroWinRx uint64 `db:"zero_win_rx"`
}

func (a *TCPPacketAnomaly) Reverse() {
	a.RetransTx, a.RetransRx = a.RetransRx, a.RetransTx
	a.ZeroWinTx, a.ZeroWinRx = a.ZeroWinRx, a.ZeroWinTx
}

func (a *TCPPacketAnomaly) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(a.RetransTx)
	encoder.WriteVarintU64(a.RetransRx)
	encoder.WriteVarintU64(a.ZeroWinTx)
	encoder.WriteVarintU64(a.ZeroWinRx)
}

func (a *TCPPacketAnomaly) Decode(decoder *codec.SimpleDecoder) {
	a.RetransTx = decoder.ReadVarintU64()
	a.RetransRx = decoder.ReadVarintU64()
	a.ZeroWinTx = decoder.ReadVarintU64()
	a.ZeroWinRx = decoder.ReadVarintU64()
}

func (a *TCPPacketAnomaly) ConcurrentMerge(other *TCPPacketAnomaly) {
	a.RetransTx += other.RetransTx
	a.RetransRx += other.RetransRx
	a.ZeroWinTx += other.ZeroWinTx
	a.ZeroWinRx += other.ZeroWinRx
}

func (a *TCPPacketAnomaly) SequentialMerge(other *TCPPacketAnomaly) {
	a.ConcurrentMerge(other)
}

func (a *TCPPacketAnomaly) MarshalTo(b []byte) int {
	fields := []string{
		"retrans_tx=", "retrans_rx=", "zero_win_tx=", "zero_win_rx=",
	}
	values := []uint64{
		a.RetransTx, a.RetransRx, a.ZeroWinTx, a.ZeroWinRx,
	}
	return marshalKeyValues(b, fields, values)
}

type TCPFlowAnomaly struct {
	ClientRstFlow       uint64 `db:"client_rst_flow"`
	ServerRstFlow       uint64 `db:"server_rst_flow"`
	ClientHalfOpenFlow  uint64 `db:"client_half_open_flow"`
	ServerHalfOpenFlow  uint64 `db:"server_half_open_flow"`
	ClientHalfCloseFlow uint64 `db:"client_half_close_flow"`
	ServerHalfCloseFlow uint64 `db:"server_half_close_flow"`
	TimeoutTCPFlow      uint64 `db:"timeout_tcp_flow"`
}

func (_ *TCPFlowAnomaly) Reverse() {
}

func (a *TCPFlowAnomaly) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(a.ClientRstFlow)
	encoder.WriteVarintU64(a.ServerRstFlow)
	encoder.WriteVarintU64(a.ClientHalfOpenFlow)
	encoder.WriteVarintU64(a.ServerHalfOpenFlow)
	encoder.WriteVarintU64(a.ClientHalfCloseFlow)
	encoder.WriteVarintU64(a.ServerHalfCloseFlow)
	encoder.WriteVarintU64(a.TimeoutTCPFlow)
}

func (a *TCPFlowAnomaly) Decode(decoder *codec.SimpleDecoder) {
	a.ClientRstFlow = decoder.ReadVarintU64()
	a.ServerRstFlow = decoder.ReadVarintU64()
	a.ClientHalfOpenFlow = decoder.ReadVarintU64()
	a.ServerHalfOpenFlow = decoder.ReadVarintU64()
	a.ClientHalfCloseFlow = decoder.ReadVarintU64()
	a.ServerHalfCloseFlow = decoder.ReadVarintU64()
	a.TimeoutTCPFlow = decoder.ReadVarintU64()
}

func (a *TCPFlowAnomaly) ConcurrentMerge(other *TCPFlowAnomaly) {
	a.ClientRstFlow += other.ClientRstFlow
	a.ServerRstFlow += other.ServerRstFlow
	a.ClientHalfOpenFlow += other.ClientHalfOpenFlow
	a.ServerHalfOpenFlow += other.ServerHalfOpenFlow
	a.ClientHalfCloseFlow += other.ClientHalfCloseFlow
	a.ServerHalfCloseFlow += other.ServerHalfCloseFlow
	a.TimeoutTCPFlow += other.TimeoutTCPFlow
}

func (a *TCPFlowAnomaly) SequentialMerge(other *TCPFlowAnomaly) {
	a.ConcurrentMerge(other)
}

func (a *TCPFlowAnomaly) MarshalTo(b []byte) int {
	fields := []string{
		"client_rst_flow=", "server_rst_flow=",
		"client_half_open_flow=", "server_half_open_flow=",
		"client_half_close_flow=", "server_half_close_flow=",
		"timeout_tcp_flow=",
	}
	values := []uint64{
		a.ClientRstFlow, a.ServerRstFlow,
		a.ClientHalfOpenFlow, a.ServerHalfOpenFlow,
		a.ClientHalfCloseFlow, a.ServerHalfCloseFlow,
		a.TimeoutTCPFlow,
	}
	return marshalKeyValues(b, fields, values)
}

func marshalKeyValues(b []byte, fields []string, values []uint64) int {
	if len(fields) != len(values) {
		panic("fields和values长度不相等")
	}
	offset := 0
	for i := range fields {
		v := values[i]
		if v == 0 {
			continue
		}
		if offset > 0 {
			b[offset] = ','
			offset++
		}
		offset += copy(b[offset:], fields[i])
		offset += copy(b[offset:], strconv.FormatUint(v, 10))
		b[offset] = 'i'
		offset++
	}

	return offset
}
