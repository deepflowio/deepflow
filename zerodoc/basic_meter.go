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
	Flow       uint64 `db:"flow"`
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
}

func (t *Traffic) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(t.PacketTx)
	encoder.WriteVarintU64(t.PacketRx)
	encoder.WriteVarintU64(t.ByteTx)
	encoder.WriteVarintU64(t.ByteRx)
	encoder.WriteVarintU64(t.Flow)
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
	t.Flow = decoder.ReadVarintU64()
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
	t.Flow += other.Flow
	t.NewFlow += other.NewFlow
	t.ClosedFlow += other.ClosedFlow

	t.HTTPRequest += other.HTTPRequest
	t.HTTPResponse += other.HTTPResponse
	t.DNSRequest += other.DNSRequest
	t.DNSResponse += other.DNSResponse
}

func (t *Traffic) SequentialMerge(other *Traffic) {
	t.PacketTx += other.PacketTx
	t.PacketRx += other.PacketRx
	t.ByteTx += other.ByteTx
	t.ByteRx += other.ByteRx
	t.Flow = t.ClosedFlow + other.Flow
	t.NewFlow += other.NewFlow
	t.ClosedFlow += other.ClosedFlow

	t.HTTPRequest = other.HTTPRequest
	t.HTTPResponse = other.HTTPResponse
	t.DNSRequest = other.DNSRequest
	t.DNSResponse = other.DNSResponse
}

func (t *Traffic) MarshalTo(b []byte) int {
	fields := []string{
		"packet_tx=", "packet_rx=", "byte_tx=", "byte_rx=", "flow=", "new_flow=", "closed_flow=",
		"http_request=", "http_response=", "dns_request=", "dns_response=",
	}
	values := []uint64{
		t.PacketTx, t.PacketRx, t.ByteTx, t.ByteRx, t.Flow, t.NewFlow, t.ClosedFlow,
		t.HTTPRequest, t.HTTPResponse, t.DNSRequest, t.DNSResponse,
	}
	return marshalKeyValues(b, fields, values)
}

type Latency struct {
	RTTSum       uint64 `db:"rtt_sum"`        // us
	RTTClientSum uint64 `db:"rtt_client_sum"` // us
	RTTServerSum uint64 `db:"rtt_server_sum"` // us
	SRTSum       uint64 `db:"srt_sum"`        // us
	ARTSum       uint64 `db:"art_sum"`        // us
	HTTPRRTSum   uint64 `db:"http_rrt_sum"`   // us
	DNSRRTSum    uint64 `db:"dns_rrt_sum"`    // us

	RTTCount       uint64 `db:"rtt_count"`
	RTTClientCount uint64 `db:"rtt_client_count"`
	RTTServerCount uint64 `db:"rtt_server_count"`
	SRTCount       uint64 `db:"srt_count"`
	ARTCount       uint64 `db:"art_count"`
	HTTPRRTCount   uint64 `db:"http_rrt_count"`
	DNSRRTCount    uint64 `db:"dns_rrt_count"`
}

func (_ *Latency) Reverse() {
}

func (l *Latency) Encode(encoder *codec.SimpleEncoder) {
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
	fields := []string{"rtt=", "rtt_client=", "rtt_server=", "srt=", "art=", "http_rrt=", "dns_rrt="}
	dividends := []uint64{l.RTTSum, l.RTTClientSum, l.RTTServerSum, l.SRTSum, l.ARTSum, l.HTTPRRTSum, l.DNSRRTSum}
	divisors := []uint64{l.RTTCount, l.RTTClientCount, l.RTTServerCount, l.SRTCount, l.ARTCount, l.HTTPRRTCount, l.DNSRRTCount}
	values := make([]uint64, len(dividends))
	for i, divisor := range divisors {
		if divisor == 0 {
			continue
		}
		values[i] = dividends[i] / divisor
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
	a.RetransTx, a.RetransRx = a.RetransRx, a.RetransTx
	a.ZeroWinTx, a.ZeroWinRx = a.ZeroWinRx, a.ZeroWinTx
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
		"retrans_tx=", "retrans_rx=", "zero_win_tx=", "zero_win_rx=",
	}
	values := []uint64{
		a.RetransTx, a.RetransRx, a.ZeroWinTx, a.ZeroWinRx,
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

	ClientNoResponse      uint64 `db:"client_no_response"`
	ClientSourcePortReuse uint64 `db:"client_source_port_reuse"`
	ClientSYNRetryLack    uint64 `db:"client_syn_retry_lack"`
	ServerReset           uint64 `db:"server_reset"`
	ServerNoResponse      uint64 `db:"server_no_response"`
	ServerQueueLack       uint64 `db:"server_queue_lack"`

	HTTPClientError uint64 `db:"http_client_error"`
	HTTPServerError uint64 `db:"http_server_error"`
	DNSClientError  uint64 `db:"dns_client_error"`
	DNSServerError  uint64 `db:"dns_server_error"`
}

func (_ *Anomaly) Reverse() {
}

func (a *Anomaly) Encode(encoder *codec.SimpleEncoder) {
	encoder.WriteVarintU64(a.ClientRstFlow)
	encoder.WriteVarintU64(a.ServerRstFlow)
	encoder.WriteVarintU64(a.ClientSynRepeat)
	encoder.WriteVarintU64(a.ServerSYNACKRepeat)
	encoder.WriteVarintU64(a.ClientHalfCloseFlow)
	encoder.WriteVarintU64(a.ServerHalfCloseFlow)

	encoder.WriteVarintU64(a.ClientNoResponse)
	encoder.WriteVarintU64(a.ClientSourcePortReuse)
	encoder.WriteVarintU64(a.ClientSYNRetryLack)
	encoder.WriteVarintU64(a.ServerReset)
	encoder.WriteVarintU64(a.ServerNoResponse)
	encoder.WriteVarintU64(a.ServerQueueLack)

	encoder.WriteVarintU64(a.HTTPClientError)
	encoder.WriteVarintU64(a.HTTPServerError)
	encoder.WriteVarintU64(a.DNSClientError)
	encoder.WriteVarintU64(a.DNSServerError)
}

func (a *Anomaly) Decode(decoder *codec.SimpleDecoder) {
	a.ClientRstFlow = decoder.ReadVarintU64()
	a.ServerRstFlow = decoder.ReadVarintU64()
	a.ClientSynRepeat = decoder.ReadVarintU64()
	a.ServerSYNACKRepeat = decoder.ReadVarintU64()
	a.ClientHalfCloseFlow = decoder.ReadVarintU64()
	a.ServerHalfCloseFlow = decoder.ReadVarintU64()

	a.ClientNoResponse = decoder.ReadVarintU64()
	a.ClientSourcePortReuse = decoder.ReadVarintU64()
	a.ClientSYNRetryLack = decoder.ReadVarintU64()
	a.ServerReset = decoder.ReadVarintU64()
	a.ServerNoResponse = decoder.ReadVarintU64()
	a.ServerQueueLack = decoder.ReadVarintU64()

	a.HTTPClientError = decoder.ReadVarintU64()
	a.HTTPServerError = decoder.ReadVarintU64()
	a.DNSClientError = decoder.ReadVarintU64()
	a.DNSServerError = decoder.ReadVarintU64()
}

func (a *Anomaly) ConcurrentMerge(other *Anomaly) {
	a.ClientRstFlow += other.ClientRstFlow
	a.ServerRstFlow += other.ServerRstFlow
	a.ClientSynRepeat += other.ClientSynRepeat
	a.ServerSYNACKRepeat += other.ServerSYNACKRepeat
	a.ClientHalfCloseFlow += other.ClientHalfCloseFlow
	a.ServerHalfCloseFlow += other.ServerHalfCloseFlow

	a.ClientNoResponse += other.ClientNoResponse
	a.ClientSourcePortReuse += other.ClientSourcePortReuse
	a.ClientSYNRetryLack += other.ClientSYNRetryLack
	a.ServerReset += other.ServerReset
	a.ServerNoResponse += other.ServerNoResponse
	a.ServerQueueLack += other.ServerQueueLack

	a.HTTPClientError += other.HTTPClientError
	a.HTTPServerError += other.HTTPServerError
	a.DNSClientError += other.DNSClientError
	a.DNSServerError += other.DNSServerError
}

func (a *Anomaly) SequentialMerge(other *Anomaly) {
	a.ConcurrentMerge(other)
}

func (a *Anomaly) MarshalTo(b []byte) int {
	fields := []string{
		"client_rst_flow=", "server_rst_flow=",
		"client_syn_repeat=", "server_syn_ack_repeat=",
		"client_half_close_flow=", "server_half_close_flow=",
		"client_no_response=", "client_source_port_reuse=",
		"client_syn_retry_lack=", "server_reset=",
		"server_no_response=", "server_queue_lack=",
		"http_client_error=", "http_server_error=",
		"dns_client_error=", "dns_server_error=",
	}
	values := []uint64{
		a.ClientRstFlow, a.ServerRstFlow,
		a.ClientSynRepeat, a.ServerSYNACKRepeat,
		a.ClientHalfCloseFlow, a.ServerHalfCloseFlow,
		a.ClientNoResponse, a.ClientSourcePortReuse,
		a.ClientSYNRetryLack, a.ServerReset,
		a.ServerNoResponse, a.ServerQueueLack,
		a.HTTPClientError, a.HTTPServerError,
		a.DNSClientError, a.DNSServerError,
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
