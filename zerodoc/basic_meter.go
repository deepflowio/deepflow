package zerodoc

import (
	"strconv"

	"gitlab.x.lan/yunshan/droplet-libs/codec"
)

type Traffic struct {
	PacketTx   uint64 `db:"packet_tx"`
	PacketRx   uint64 `db:"packet_rx"`
	ByteTx     uint64 `db:"byte_tx"`
	ByteRx     uint64 `db:"byte_rx"`
	L3ByteTx   uint64 `db:"l3_byte_tx"`
	L3ByteRx   uint64 `db:"l3_byte_rx"`
	L4ByteTx   uint64 `db:"l4_byte_tx"`
	L4ByteRx   uint64 `db:"l4_byte_rx"`
	NewFlow    uint64 `db:"new_flow"`
	ClosedFlow uint64 `db:"closed_flow"`

	HTTPRequest  uint64 `db:"http_request"`
	HTTPResponse uint64 `db:"http_response"`
	DNSRequest   uint64 `db:"dns_request"`
	DNSResponse  uint64 `db:"dns_response"`
}

func (t *Traffic) Reverse() {
	t.PacketTx, t.PacketRx = t.PacketRx, t.PacketTx
	t.ByteTx, t.ByteRx = t.ByteRx, t.ByteTx
	t.L3ByteTx, t.L3ByteRx = t.L3ByteRx, t.L3ByteTx
	t.L4ByteTx, t.L4ByteRx = t.L4ByteRx, t.L4ByteTx

	// HTTP、DNS统计量以客户端、服务端为视角，无需Reverse
}

func (t *Traffic) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(t.PacketTx)
	encoder.WriteVarintU64(t.PacketRx)
	encoder.WriteVarintU64(t.ByteTx)
	encoder.WriteVarintU64(t.ByteRx)
	encoder.WriteVarintU64(t.L3ByteTx)
	encoder.WriteVarintU64(t.L3ByteRx)
	encoder.WriteVarintU64(t.L4ByteTx)
	encoder.WriteVarintU64(t.L4ByteRx)
	encoder.WriteVarintU64(t.NewFlow)
	encoder.WriteVarintU64(t.ClosedFlow)

	encoder.WriteVarintU64(t.HTTPRequest)
	encoder.WriteVarintU64(t.HTTPResponse)
	encoder.WriteVarintU64(t.DNSRequest)
	encoder.WriteVarintU64(t.DNSResponse)
}

func (t *Traffic) Decode(decoder *codec.SimpleDecoder) {
	t.PacketTx = decoder.ReadVarintU64()
	t.PacketRx = decoder.ReadVarintU64()
	t.ByteTx = decoder.ReadVarintU64()
	t.ByteRx = decoder.ReadVarintU64()
	t.L3ByteTx = decoder.ReadVarintU64()
	t.L3ByteRx = decoder.ReadVarintU64()
	t.L4ByteTx = decoder.ReadVarintU64()
	t.L4ByteRx = decoder.ReadVarintU64()
	t.NewFlow = decoder.ReadVarintU64()
	t.ClosedFlow = decoder.ReadVarintU64()

	t.HTTPRequest = decoder.ReadVarintU64()
	t.HTTPResponse = decoder.ReadVarintU64()
	t.DNSRequest = decoder.ReadVarintU64()
	t.DNSResponse = decoder.ReadVarintU64()
}

func (t *Traffic) ConcurrentMerge(other *Traffic) {
	t.PacketTx += other.PacketTx
	t.PacketRx += other.PacketRx
	t.ByteTx += other.ByteTx
	t.ByteRx += other.ByteRx
	t.L3ByteTx += other.L3ByteTx
	t.L3ByteRx += other.L3ByteRx
	t.L4ByteTx += other.L4ByteTx
	t.L4ByteRx += other.L4ByteRx
	t.NewFlow += other.NewFlow
	t.ClosedFlow += other.ClosedFlow

	t.HTTPRequest += other.HTTPRequest
	t.HTTPResponse += other.HTTPResponse
	t.DNSRequest += other.DNSRequest
	t.DNSResponse += other.DNSResponse
}

func (t *Traffic) SequentialMerge(other *Traffic) {
	t.ConcurrentMerge(other)
}

func (t *Traffic) MarshalTo(b []byte) int {
	// 保证packet一定会写入，用于查询时，若只查tag不查field，则需要默认查询field 'packet'
	offset := 0
	offset += copy(b[offset:], "packet=")
	offset += copy(b[offset:], strconv.FormatUint(t.PacketTx+t.PacketRx, 10))
	offset += copy(b[offset:], "i,") // 先加',',若后续若没有增加数据，需要去除

	fields := []string{
		"packet_tx=", "packet_rx=", "byte_tx=", "byte_rx=", "byte=", "l3_byte_tx=", "l3_byte_rx=", "l4_byte_tx=", "l4_byte_rx=", "new_flow=", "closed_flow=",
		"http_request=", "http_response=", "dns_request=", "dns_response=",
	}
	values := []uint64{
		t.PacketTx, t.PacketRx, t.ByteTx, t.ByteRx, t.ByteTx + t.ByteRx, t.L3ByteTx, t.L3ByteRx, t.L4ByteTx, t.L4ByteRx, t.NewFlow, t.ClosedFlow,
		t.HTTPRequest, t.HTTPResponse, t.DNSRequest, t.DNSResponse,
	}
	n := marshalKeyValues(b[offset:], fields, values)
	if n == 0 {
		offset-- // 去除','
	}
	return offset + n
}

type Latency struct {
	RTTMax       uint32 `db:"rtt_max"`        // us，Trident保证时延最大值不会超过3600s，能容纳在u32内
	RTTClientMax uint32 `db:"rtt_client_max"` // us
	RTTServerMax uint32 `db:"rtt_server_max"` // us
	SRTMax       uint32 `db:"srt_max"`        // us
	ARTMax       uint32 `db:"art_max"`        // us
	HTTPRRTMax   uint32 `db:"http_rrt_max"`   // us
	DNSRRTMax    uint32 `db:"dns_rrt_max"`    // us

	RTTSum       uint64 `db:"rtt_sum"`        // us
	RTTClientSum uint64 `db:"rtt_client_sum"` // us
	RTTServerSum uint64 `db:"rtt_server_sum"` // us
	SRTSum       uint64 `db:"srt_sum"`        // us
	ARTSum       uint64 `db:"art_sum"`        // us
	HTTPRRTSum   uint64 `db:"http_rrt_sum"`   // us
	DNSRRTSum    uint64 `db:"dns_rrt_sum"`    // us

	RTTCount       uint64 `db:"rtt_count"` // XXX：考虑优化为u32，因为1分钟内时延计算量预期应该在40亿次以内
	RTTClientCount uint64 `db:"rtt_client_count"`
	RTTServerCount uint64 `db:"rtt_server_count"`
	SRTCount       uint64 `db:"srt_count"`
	ARTCount       uint64 `db:"art_count"`
	HTTPRRTCount   uint64 `db:"http_rrt_count"`
	DNSRRTCount    uint64 `db:"dns_rrt_count"`
}

func (_ *Latency) Reverse() {
	// 时延统计量以客户端、服务端为视角，无需Reverse
}

func (l *Latency) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU32(l.RTTMax)
	encoder.WriteVarintU32(l.RTTClientMax)
	encoder.WriteVarintU32(l.RTTServerMax)
	encoder.WriteVarintU32(l.SRTMax)
	encoder.WriteVarintU32(l.ARTMax)
	encoder.WriteVarintU32(l.HTTPRRTMax)
	encoder.WriteVarintU32(l.DNSRRTMax)

	encoder.WriteVarintU64(l.RTTSum)
	encoder.WriteVarintU64(l.RTTClientSum)
	encoder.WriteVarintU64(l.RTTServerSum)
	encoder.WriteVarintU64(l.SRTSum)
	encoder.WriteVarintU64(l.ARTSum)
	encoder.WriteVarintU64(l.HTTPRRTSum)
	encoder.WriteVarintU64(l.DNSRRTSum)

	encoder.WriteVarintU64(l.RTTCount)
	encoder.WriteVarintU64(l.RTTClientCount)
	encoder.WriteVarintU64(l.RTTServerCount)
	encoder.WriteVarintU64(l.SRTCount)
	encoder.WriteVarintU64(l.ARTCount)
	encoder.WriteVarintU64(l.HTTPRRTCount)
	encoder.WriteVarintU64(l.DNSRRTCount)
}

func (l *Latency) Decode(decoder *codec.SimpleDecoder) {
	l.RTTMax = decoder.ReadVarintU32()
	l.RTTClientMax = decoder.ReadVarintU32()
	l.RTTServerMax = decoder.ReadVarintU32()
	l.SRTMax = decoder.ReadVarintU32()
	l.ARTMax = decoder.ReadVarintU32()
	l.HTTPRRTMax = decoder.ReadVarintU32()
	l.DNSRRTMax = decoder.ReadVarintU32()

	l.RTTSum = decoder.ReadVarintU64()
	l.RTTClientSum = decoder.ReadVarintU64()
	l.RTTServerSum = decoder.ReadVarintU64()
	l.SRTSum = decoder.ReadVarintU64()
	l.ARTSum = decoder.ReadVarintU64()
	l.HTTPRRTSum = decoder.ReadVarintU64()
	l.DNSRRTSum = decoder.ReadVarintU64()

	l.RTTCount = decoder.ReadVarintU64()
	l.RTTClientCount = decoder.ReadVarintU64()
	l.RTTServerCount = decoder.ReadVarintU64()
	l.SRTCount = decoder.ReadVarintU64()
	l.ARTCount = decoder.ReadVarintU64()
	l.HTTPRRTCount = decoder.ReadVarintU64()
	l.DNSRRTCount = decoder.ReadVarintU64()
}

func (l *Latency) ConcurrentMerge(other *Latency) {
	if l.RTTMax < other.RTTMax {
		l.RTTMax = other.RTTMax
	}
	if l.RTTClientMax < other.RTTClientMax {
		l.RTTClientMax = other.RTTClientMax
	}
	if l.RTTServerMax < other.RTTServerMax {
		l.RTTServerMax = other.RTTServerMax
	}
	if l.SRTMax < other.SRTMax {
		l.SRTMax = other.SRTMax
	}
	if l.ARTMax < other.ARTMax {
		l.ARTMax = other.ARTMax
	}
	if l.HTTPRRTMax < other.HTTPRRTMax {
		l.HTTPRRTMax = other.HTTPRRTMax
	}
	if l.DNSRRTMax < other.DNSRRTMax {
		l.DNSRRTMax = other.DNSRRTMax
	}

	l.RTTSum += other.RTTSum
	l.RTTClientSum += other.RTTClientSum
	l.RTTServerSum += other.RTTServerSum
	l.SRTSum += other.SRTSum
	l.ARTSum += other.ARTSum
	l.HTTPRRTSum += other.HTTPRRTSum
	l.DNSRRTSum += other.DNSRRTSum

	l.RTTCount += other.RTTCount
	l.RTTClientCount += other.RTTClientCount
	l.RTTServerCount += other.RTTServerCount
	l.SRTCount += other.SRTCount
	l.ARTCount += other.ARTCount
	l.HTTPRRTCount += other.HTTPRRTCount
	l.DNSRRTCount += other.DNSRRTCount

}

func (l *Latency) SequentialMerge(other *Latency) {
	l.ConcurrentMerge(other)
}

func (l *Latency) MarshalTo(b []byte) int {
	fields := []string{"rtt_sum=", "rtt_client_sum=", "rtt_server_sum=", "srt_sum=", "art_sum=", "http_rrt_sum=", "dns_rrt_sum=",
		"rtt_count=", "rtt_client_count=", "rtt_server_count=", "srt_count=", "art_count=", "http_rrt_count=", "dns_rrt_count=",
		"rtt_max=", "rtt_client_max=", "rtt_server_max=", "srt_max=", "art_max=", "http_rrt_max=", "dns_rrt_max="}
	values := []uint64{
		l.RTTSum, l.RTTClientSum, l.RTTServerSum, l.SRTSum, l.ARTSum, l.HTTPRRTSum, l.DNSRRTSum,
		l.RTTCount, l.RTTClientCount, l.RTTServerCount, l.SRTCount, l.ARTCount, l.HTTPRRTCount, l.DNSRRTCount,
		uint64(l.RTTMax), uint64(l.RTTClientMax), uint64(l.RTTServerMax), uint64(l.SRTMax), uint64(l.ARTMax), uint64(l.HTTPRRTMax), uint64(l.DNSRRTMax),
	}
	return marshalKeyValues(b, fields, values)
}

type Performance struct {
	RetransTx uint64 `db:"retrans_tx"`
	RetransRx uint64 `db:"retrans_rx"`
	ZeroWinTx uint64 `db:"zero_win_tx"`
	ZeroWinRx uint64 `db:"zero_win_rx"`
}

func (a *Performance) Reverse() {
	// 性能统计量以客户端、服务端为视角，无需Reverse
}

func (a *Performance) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(a.RetransTx)
	encoder.WriteVarintU64(a.RetransRx)
	encoder.WriteVarintU64(a.ZeroWinTx)
	encoder.WriteVarintU64(a.ZeroWinRx)
}

func (a *Performance) Decode(decoder *codec.SimpleDecoder) {
	a.RetransTx = decoder.ReadVarintU64()
	a.RetransRx = decoder.ReadVarintU64()
	a.ZeroWinTx = decoder.ReadVarintU64()
	a.ZeroWinRx = decoder.ReadVarintU64()
}

func (a *Performance) ConcurrentMerge(other *Performance) {
	a.RetransTx += other.RetransTx
	a.RetransRx += other.RetransRx
	a.ZeroWinTx += other.ZeroWinTx
	a.ZeroWinRx += other.ZeroWinRx
}

func (a *Performance) SequentialMerge(other *Performance) {
	a.ConcurrentMerge(other)
}

func (a *Performance) MarshalTo(b []byte) int {
	fields := []string{
		"retrans_tx=", "retrans_rx=", "retrans=", "zero_win_tx=", "zero_win_rx=", "zero_win=",
	}
	values := []uint64{
		a.RetransTx, a.RetransRx, a.RetransTx + a.RetransRx, a.ZeroWinTx, a.ZeroWinRx, a.ZeroWinTx + a.ZeroWinRx,
	}
	return marshalKeyValues(b, fields, values)
}

type Anomaly struct {
	ClientRstFlow       uint64 `db:"client_rst_flow"`
	ServerRstFlow       uint64 `db:"server_rst_flow"`
	ClientSynRepeat     uint64 `db:"client_syn_repeat"`
	ServerSYNACKRepeat  uint64 `db:"server_syn_ack_repeat"`
	ClientHalfCloseFlow uint64 `db:"client_half_close_flow"`
	ServerHalfCloseFlow uint64 `db:"server_half_close_flow"`

	ClientSourcePortReuse uint64 `db:"client_source_port_reuse"`
	ClientEstablishReset  uint64 `db:"client_establish_other_rst"`
	ServerReset           uint64 `db:"server_reset"`
	ServerQueueLack       uint64 `db:"server_queue_lack"`
	ServerEstablishReset  uint64 `db:"server_establish_other_rst"`
	TCPTimeout            uint64 `db:"tcp_timeout"`

	HTTPClientError uint64 `db:"http_client_error"`
	HTTPServerError uint64 `db:"http_server_error"`
	HTTPTimeout     uint64 `db:"http_timeout"`
	DNSClientError  uint64 `db:"dns_client_error"`
	DNSServerError  uint64 `db:"dns_server_error"`
	DNSTimeout      uint64 `db:"dns_timeout"`
}

func (_ *Anomaly) Reverse() {
	// 异常统计量以客户端、服务端为视角，无需Reverse
}

func (a *Anomaly) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(a.ClientRstFlow)
	encoder.WriteVarintU64(a.ServerRstFlow)
	encoder.WriteVarintU64(a.ClientSynRepeat)
	encoder.WriteVarintU64(a.ServerSYNACKRepeat)
	encoder.WriteVarintU64(a.ClientHalfCloseFlow)
	encoder.WriteVarintU64(a.ServerHalfCloseFlow)

	encoder.WriteVarintU64(a.ClientSourcePortReuse)
	encoder.WriteVarintU64(a.ClientEstablishReset)
	encoder.WriteVarintU64(a.ServerReset)
	encoder.WriteVarintU64(a.ServerQueueLack)
	encoder.WriteVarintU64(a.ServerEstablishReset)
	encoder.WriteVarintU64(a.TCPTimeout)

	encoder.WriteVarintU64(a.HTTPClientError)
	encoder.WriteVarintU64(a.HTTPServerError)
	encoder.WriteVarintU64(a.HTTPTimeout)
	encoder.WriteVarintU64(a.DNSClientError)
	encoder.WriteVarintU64(a.DNSServerError)
	encoder.WriteVarintU64(a.DNSTimeout)
}

func (a *Anomaly) Decode(decoder *codec.SimpleDecoder) {
	a.ClientRstFlow = decoder.ReadVarintU64()
	a.ServerRstFlow = decoder.ReadVarintU64()
	a.ClientSynRepeat = decoder.ReadVarintU64()
	a.ServerSYNACKRepeat = decoder.ReadVarintU64()
	a.ClientHalfCloseFlow = decoder.ReadVarintU64()
	a.ServerHalfCloseFlow = decoder.ReadVarintU64()

	a.ClientSourcePortReuse = decoder.ReadVarintU64()
	a.ClientEstablishReset = decoder.ReadVarintU64()
	a.ServerReset = decoder.ReadVarintU64()
	a.ServerQueueLack = decoder.ReadVarintU64()
	a.ServerEstablishReset = decoder.ReadVarintU64()
	a.TCPTimeout = decoder.ReadVarintU64()

	a.HTTPClientError = decoder.ReadVarintU64()
	a.HTTPServerError = decoder.ReadVarintU64()
	a.HTTPTimeout = decoder.ReadVarintU64()
	a.DNSClientError = decoder.ReadVarintU64()
	a.DNSServerError = decoder.ReadVarintU64()
	a.DNSTimeout = decoder.ReadVarintU64()
}

func (a *Anomaly) ConcurrentMerge(other *Anomaly) {
	a.ClientRstFlow += other.ClientRstFlow
	a.ServerRstFlow += other.ServerRstFlow
	a.ClientSynRepeat += other.ClientSynRepeat
	a.ServerSYNACKRepeat += other.ServerSYNACKRepeat
	a.ClientHalfCloseFlow += other.ClientHalfCloseFlow
	a.ServerHalfCloseFlow += other.ServerHalfCloseFlow

	a.ClientSourcePortReuse += other.ClientSourcePortReuse
	a.ClientEstablishReset += other.ClientEstablishReset
	a.ServerReset += other.ServerReset
	a.ServerQueueLack += other.ServerQueueLack
	a.ServerEstablishReset += other.ServerEstablishReset
	a.TCPTimeout += other.TCPTimeout

	a.HTTPClientError += other.HTTPClientError
	a.HTTPServerError += other.HTTPServerError
	a.HTTPTimeout += other.HTTPTimeout

	a.DNSClientError += other.DNSClientError
	a.DNSServerError += other.DNSServerError
	a.DNSTimeout += other.DNSTimeout
}

func (a *Anomaly) SequentialMerge(other *Anomaly) {
	a.ConcurrentMerge(other)
}

func (a *Anomaly) MarshalTo(b []byte) int {
	fields := []string{
		"client_rst_flow=", "server_rst_flow=",
		"client_syn_repeat=", "server_syn_ack_repeat=",
		"client_half_close_flow=", "server_half_close_flow=",
		"client_source_port_reuse=", "server_reset=", "server_queue_lack=",
		"client_establish_other_rst=", "server_establish_other_rst=",
		"tcp_timeout=",
		"client_establish_fail=", "server_establish_fail=", "tcp_establish_fail=",
		"http_client_error=", "http_server_error=", "http_timeout=", "http_error=",
		"dns_client_error=", "dns_server_error=", "dns_timeout=", "dns_error=",
	}
	clientFail := a.ClientSynRepeat + a.ClientSourcePortReuse + a.ClientEstablishReset
	serverFail := a.ServerSYNACKRepeat + a.ServerReset + a.ServerQueueLack + a.ServerEstablishReset
	values := []uint64{
		a.ClientRstFlow, a.ServerRstFlow,
		a.ClientSynRepeat, a.ServerSYNACKRepeat,
		a.ClientHalfCloseFlow, a.ServerHalfCloseFlow,
		a.ClientSourcePortReuse, a.ServerReset, a.ServerQueueLack,
		a.ClientEstablishReset, a.ServerEstablishReset,
		a.TCPTimeout,
		clientFail, serverFail, clientFail + serverFail,
		a.HTTPClientError, a.HTTPServerError, a.HTTPTimeout, a.HTTPClientError + a.HTTPServerError,
		a.DNSClientError, a.DNSServerError, a.DNSTimeout, a.DNSClientError + a.DNSServerError,
	}
	return marshalKeyValues(b, fields, values)
}

type FlowLoad struct {
	Load uint64 `db:"flow_load"`
}

func (l *FlowLoad) Reverse() {
	// 负载统计量无方向，无需Reverse
}

func (l *FlowLoad) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(l.Load)
}

func (l *FlowLoad) Decode(decoder *codec.SimpleDecoder) {
	l.Load = decoder.ReadVarintU64()
}

func (l *FlowLoad) ConcurrentMerge(other *FlowLoad) {
	l.Load += other.Load
}

func (l *FlowLoad) SequentialMerge(other *FlowLoad) {
	l.ConcurrentMerge(other)
}

func (l *FlowLoad) MarshalTo(b []byte) int {
	fields := []string{"flow_load="}
	values := []uint64{l.Load}
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
