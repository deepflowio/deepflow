package zerodoc

import (
	"strconv"

	"gitlab.yunshan.net/yunshan/droplet-libs/ckdb"
	"gitlab.yunshan.net/yunshan/droplet-libs/codec"
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

	HTTPRequest   uint32 `db:"http_request"`
	HTTPResponse  uint32 `db:"http_response"`
	DNSRequest    uint32 `db:"dns_request"`
	DNSResponse   uint32 `db:"dns_response"`
	MYSQLRequest  uint32 `db:"mysql_request"`
	MYSQLResponse uint32 `db:"mysql_response"`
	REDISRequest  uint32 `db:"redis_request"`
	REDISResponse uint32 `db:"redis_response"`
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

	encoder.WriteVarintU32(t.HTTPRequest)
	encoder.WriteVarintU32(t.HTTPResponse)
	encoder.WriteVarintU32(t.DNSRequest)
	encoder.WriteVarintU32(t.DNSResponse)
	encoder.WriteVarintU32(t.MYSQLRequest)
	encoder.WriteVarintU32(t.MYSQLResponse)
	encoder.WriteVarintU32(t.REDISRequest)
	encoder.WriteVarintU32(t.REDISResponse)
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

	t.HTTPRequest = decoder.ReadVarintU32()
	t.HTTPResponse = decoder.ReadVarintU32()
	t.DNSRequest = decoder.ReadVarintU32()
	t.DNSResponse = decoder.ReadVarintU32()
	t.MYSQLRequest = decoder.ReadVarintU32()
	t.MYSQLResponse = decoder.ReadVarintU32()
	t.REDISRequest = decoder.ReadVarintU32()
	t.REDISResponse = decoder.ReadVarintU32()
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
	t.MYSQLRequest += other.MYSQLRequest
	t.MYSQLResponse += other.MYSQLResponse
	t.REDISRequest += other.REDISRequest
	t.REDISResponse += other.REDISResponse
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
		"http_request=", "http_response=", "dns_request=", "dns_response=", "mysql_request=", "mysql_response=", "redis_request=", "redis_response=",
	}
	values := []uint64{
		t.PacketTx, t.PacketRx, t.ByteTx, t.ByteRx, t.ByteTx + t.ByteRx, t.L3ByteTx, t.L3ByteRx, t.L4ByteTx, t.L4ByteRx, t.NewFlow, t.ClosedFlow,
		uint64(t.HTTPRequest), uint64(t.HTTPResponse),
		uint64(t.DNSRequest), uint64(t.DNSResponse),
		uint64(t.MYSQLRequest), uint64(t.MYSQLResponse),
		uint64(t.REDISRequest), uint64(t.REDISResponse),
	}
	n := marshalKeyValues(b[offset:], fields, values)
	if n == 0 {
		offset-- // 去除','
	}
	return offset + n
}

const (
	TRAFFIC_PACKET_TX = iota
	TRAFFIC_PACKET_RX
	TRAFFIC_PACKET

	TRAFFIC_BYTE_TX
	TRAFFIC_BYTE_RX
	TRAFFIC_BYTE

	TRAFFIC_L3_BYTE_TX
	TRAFFIC_L3_BYTE_RX
	TRAFFIC_L4_BYTE_TX
	TRAFFIC_L4_BYTE_RX

	TRAFFIC_NEW_FLOW
	TRAFFIC_CLOSED_FLOW

	TRAFFIC_HTTP_REQUEST
	TRAFFIC_HTTP_RESPONSE
	TRAFFIC_DNS_REQUEST
	TRAFFIC_DNS_RESPONSE
	TRAFFIC_MYSQL_REQUEST
	TRAFFIC_MYSQL_RESPONSE
	TRAFFIC_REDIS_REQUEST
	TRAFFIC_REDIS_RESPONSE
)

// Columns列和WriteBlock的列需要按顺序一一对应
func TrafficColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment(
		[][2]string{
			TRAFFIC_PACKET_TX: {"packet_tx", "累计发送总包数"},
			TRAFFIC_PACKET_RX: {"packet_rx", "累计接收总包数"},
			TRAFFIC_PACKET:    {"packet", "累计总包数"},

			TRAFFIC_BYTE_TX: {"byte_tx", "累计发送总字节数"},
			TRAFFIC_BYTE_RX: {"byte_rx", "累计接收总字节数"},
			TRAFFIC_BYTE:    {"byte", "累计总字节数"},

			TRAFFIC_L3_BYTE_TX: {"l3_byte_tx", "累计发送网络层负载总字节数"},
			TRAFFIC_L3_BYTE_RX: {"l3_byte_rx", "累计接收网络层负载总字节数"},
			TRAFFIC_L4_BYTE_TX: {"l4_byte_tx", "累计发送应用层负载总字节数"},
			TRAFFIC_L4_BYTE_RX: {"l4_byte_rx", "累计接收应用层负载总字节数"},

			TRAFFIC_NEW_FLOW:    {"new_flow", "累计新建连接数"},
			TRAFFIC_CLOSED_FLOW: {"closed_flow", "累计关闭连接数"},

			TRAFFIC_HTTP_REQUEST:   {"http_request", "累计HTTP请求包数"},
			TRAFFIC_HTTP_RESPONSE:  {"http_response", "累计HTTP响应包数"},
			TRAFFIC_DNS_REQUEST:    {"dns_request", "累计DNS请求包数"},
			TRAFFIC_DNS_RESPONSE:   {"dns_response", "累计DNS响应包数"},
			TRAFFIC_MYSQL_REQUEST:  {"mysql_request", "累计MYSQL请求包数"},
			TRAFFIC_MYSQL_RESPONSE: {"mysql_response", "累计MYSQL响应包数"},
			TRAFFIC_REDIS_REQUEST:  {"redis_request", "累计REDIS请求包数"},
			TRAFFIC_REDIS_RESPONSE: {"redis_response", "累计REDIS响应包数"},
		},
		ckdb.UInt64)
}

// WriteBlock的列需和Columns 按顺序一一对应
func (t *Traffic) WriteBlock(block *ckdb.Block) error {
	values := []uint64{
		TRAFFIC_PACKET_TX: t.PacketTx,
		TRAFFIC_PACKET_RX: t.PacketRx,
		TRAFFIC_PACKET:    t.PacketTx + t.PacketRx,

		TRAFFIC_BYTE_TX: t.ByteTx,
		TRAFFIC_BYTE_RX: t.ByteRx,
		TRAFFIC_BYTE:    t.ByteTx + t.ByteRx,

		TRAFFIC_L3_BYTE_TX: t.L3ByteTx,
		TRAFFIC_L3_BYTE_RX: t.L3ByteRx,
		TRAFFIC_L4_BYTE_TX: t.L4ByteTx,
		TRAFFIC_L4_BYTE_RX: t.L4ByteRx,

		TRAFFIC_NEW_FLOW:    t.NewFlow,
		TRAFFIC_CLOSED_FLOW: t.ClosedFlow,

		TRAFFIC_HTTP_REQUEST:   uint64(t.HTTPRequest),
		TRAFFIC_HTTP_RESPONSE:  uint64(t.HTTPResponse),
		TRAFFIC_DNS_REQUEST:    uint64(t.DNSRequest),
		TRAFFIC_DNS_RESPONSE:   uint64(t.DNSResponse),
		TRAFFIC_MYSQL_REQUEST:  uint64(t.MYSQLRequest),
		TRAFFIC_MYSQL_RESPONSE: uint64(t.MYSQLResponse),
		TRAFFIC_REDIS_REQUEST:  uint64(t.REDISRequest),
		TRAFFIC_REDIS_RESPONSE: uint64(t.REDISResponse),
	}
	for _, v := range values {
		if err := block.WriteUInt64(v); err != nil {
			return err
		}
	}
	return nil
}

type Latency struct {
	RTTMax       uint32 `db:"rtt_max"`        // us，Trident保证时延最大值不会超过3600s，能容纳在u32内
	RTTClientMax uint32 `db:"rtt_client_max"` // us
	RTTServerMax uint32 `db:"rtt_server_max"` // us
	SRTMax       uint32 `db:"srt_max"`        // us
	ARTMax       uint32 `db:"art_max"`        // us
	HTTPRRTMax   uint32 `db:"http_rrt_max"`   // us
	DNSRRTMax    uint32 `db:"dns_rrt_max"`    // us
	MYSQLRRTMax  uint32 `db:"mysql_rrt_max"`  // us
	REDISRRTMax  uint32 `db:"redis_rrt_max"`  // us

	RTTSum       uint64 `db:"rtt_sum"`        // us
	RTTClientSum uint64 `db:"rtt_client_sum"` // us
	RTTServerSum uint64 `db:"rtt_server_sum"` // us
	SRTSum       uint64 `db:"srt_sum"`        // us
	ARTSum       uint64 `db:"art_sum"`        // us
	HTTPRRTSum   uint64 `db:"http_rrt_sum"`   // us
	DNSRRTSum    uint64 `db:"dns_rrt_sum"`    // us
	MYSQLRRTSum  uint64 `db:"mysql_rrt_sum"`  // us
	REDISRRTSum  uint64 `db:"redis_rrt_sum"`  // us

	RTTCount       uint32 `db:"rtt_count"`
	RTTClientCount uint32 `db:"rtt_client_count"`
	RTTServerCount uint32 `db:"rtt_server_count"`
	SRTCount       uint32 `db:"srt_count"`
	ARTCount       uint32 `db:"art_count"`
	HTTPRRTCount   uint32 `db:"http_rrt_count"`
	DNSRRTCount    uint32 `db:"dns_rrt_count"`
	MYSQLRRTCount  uint32 `db:"mysql_rrt_count"`
	REDISRRTCount  uint32 `db:"redis_rrt_count"`
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
	encoder.WriteVarintU32(l.MYSQLRRTMax)
	encoder.WriteVarintU32(l.REDISRRTMax)

	encoder.WriteVarintU64(l.RTTSum)
	encoder.WriteVarintU64(l.RTTClientSum)
	encoder.WriteVarintU64(l.RTTServerSum)
	encoder.WriteVarintU64(l.SRTSum)
	encoder.WriteVarintU64(l.ARTSum)
	encoder.WriteVarintU64(l.HTTPRRTSum)
	encoder.WriteVarintU64(l.DNSRRTSum)
	encoder.WriteVarintU64(l.MYSQLRRTSum)
	encoder.WriteVarintU64(l.REDISRRTSum)

	encoder.WriteVarintU32(l.RTTCount)
	encoder.WriteVarintU32(l.RTTClientCount)
	encoder.WriteVarintU32(l.RTTServerCount)
	encoder.WriteVarintU32(l.SRTCount)
	encoder.WriteVarintU32(l.ARTCount)
	encoder.WriteVarintU32(l.HTTPRRTCount)
	encoder.WriteVarintU32(l.DNSRRTCount)
	encoder.WriteVarintU32(l.MYSQLRRTCount)
	encoder.WriteVarintU32(l.REDISRRTCount)
}

func (l *Latency) Decode(decoder *codec.SimpleDecoder) {
	l.RTTMax = decoder.ReadVarintU32()
	l.RTTClientMax = decoder.ReadVarintU32()
	l.RTTServerMax = decoder.ReadVarintU32()
	l.SRTMax = decoder.ReadVarintU32()
	l.ARTMax = decoder.ReadVarintU32()
	l.HTTPRRTMax = decoder.ReadVarintU32()
	l.DNSRRTMax = decoder.ReadVarintU32()
	l.MYSQLRRTMax = decoder.ReadVarintU32()
	l.REDISRRTMax = decoder.ReadVarintU32()

	l.RTTSum = decoder.ReadVarintU64()
	l.RTTClientSum = decoder.ReadVarintU64()
	l.RTTServerSum = decoder.ReadVarintU64()
	l.SRTSum = decoder.ReadVarintU64()
	l.ARTSum = decoder.ReadVarintU64()
	l.HTTPRRTSum = decoder.ReadVarintU64()
	l.DNSRRTSum = decoder.ReadVarintU64()
	l.MYSQLRRTSum = decoder.ReadVarintU64()
	l.REDISRRTSum = decoder.ReadVarintU64()

	l.RTTCount = decoder.ReadVarintU32()
	l.RTTClientCount = decoder.ReadVarintU32()
	l.RTTServerCount = decoder.ReadVarintU32()
	l.SRTCount = decoder.ReadVarintU32()
	l.ARTCount = decoder.ReadVarintU32()
	l.HTTPRRTCount = decoder.ReadVarintU32()
	l.DNSRRTCount = decoder.ReadVarintU32()
	l.MYSQLRRTCount = decoder.ReadVarintU32()
	l.REDISRRTCount = decoder.ReadVarintU32()
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
	if l.MYSQLRRTMax < other.MYSQLRRTMax {
		l.MYSQLRRTMax = other.MYSQLRRTMax
	}
	if l.REDISRRTMax < other.REDISRRTMax {
		l.REDISRRTMax = other.REDISRRTMax
	}

	l.RTTSum += other.RTTSum
	l.RTTClientSum += other.RTTClientSum
	l.RTTServerSum += other.RTTServerSum
	l.SRTSum += other.SRTSum
	l.ARTSum += other.ARTSum
	l.HTTPRRTSum += other.HTTPRRTSum
	l.DNSRRTSum += other.DNSRRTSum
	l.MYSQLRRTSum += other.MYSQLRRTSum
	l.REDISRRTSum += other.REDISRRTSum

	l.RTTCount += other.RTTCount
	l.RTTClientCount += other.RTTClientCount
	l.RTTServerCount += other.RTTServerCount
	l.SRTCount += other.SRTCount
	l.ARTCount += other.ARTCount
	l.HTTPRRTCount += other.HTTPRRTCount
	l.DNSRRTCount += other.DNSRRTCount
	l.MYSQLRRTCount += other.MYSQLRRTCount
	l.REDISRRTCount += other.REDISRRTCount

}

func (l *Latency) SequentialMerge(other *Latency) {
	l.ConcurrentMerge(other)
}

func (l *Latency) MarshalTo(b []byte) int {
	fields := []string{"rtt_sum=", "rtt_client_sum=", "rtt_server_sum=", "srt_sum=", "art_sum=",
		"http_rrt_sum=", "dns_rrt_sum=", "mysql_rrt_sum=", "redis_rrt_sum=",
		"rtt_count=", "rtt_client_count=", "rtt_server_count=", "srt_count=", "art_count=",
		"http_rrt_count=", "dns_rrt_count=", "mysql_rrt_count=", "redis_rrt_count=",
		"rtt_max=", "rtt_client_max=", "rtt_server_max=", "srt_max=", "art_max=",
		"http_rrt_max=", "dns_rrt_max=", "mysql_rrt_max=", "redis_rrt_max="}
	values := []uint64{
		l.RTTSum, l.RTTClientSum, l.RTTServerSum, l.SRTSum, l.ARTSum,
		l.HTTPRRTSum, l.DNSRRTSum, l.MYSQLRRTSum, l.REDISRRTSum,
		uint64(l.RTTCount), uint64(l.RTTClientCount), uint64(l.RTTServerCount), uint64(l.SRTCount), uint64(l.ARTCount),
		uint64(l.HTTPRRTCount), uint64(l.DNSRRTCount), uint64(l.MYSQLRRTCount), uint64(l.REDISRRTCount),
		uint64(l.RTTMax), uint64(l.RTTClientMax), uint64(l.RTTServerMax), uint64(l.SRTMax), uint64(l.ARTMax),
		uint64(l.HTTPRRTMax), uint64(l.DNSRRTMax), uint64(l.MYSQLRRTMax), uint64(l.REDISRRTMax),
	}
	return marshalKeyValues(b, fields, values)
}

const (
	LATENCY_RTT = iota
	LATENCY_RTT_CLIENT
	LATENCY_RTT_SERVER
	LATENCY_SRT
	LATENCY_ART
	LATENCY_HTTP_RRT
	LATENCY_DNS_RRT
	LATENCY_MYSQL_RRT
	LATENCY_REDIS_RRT
)

// Columns列和WriteBlock的列需要按顺序一一对应
func LatencyColumns() []*ckdb.Column {
	sumColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			LATENCY_RTT:        {"rtt_sum", "累计建立连接RTT(us)"},
			LATENCY_RTT_CLIENT: {"rtt_client_sum", "客户端累计建立连接RTT(us)"},
			LATENCY_RTT_SERVER: {"rtt_server_sum", "服务端累计建立连接RTT(us)"},
			LATENCY_SRT:        {"srt_sum", "累计所有系统响应时延(us)"},
			LATENCY_ART:        {"art_sum", "累计所有应用响应时延(us)"},
			LATENCY_HTTP_RRT:   {"http_rrt_sum", "累计所有HTTP请求响应时延(us)"},
			LATENCY_DNS_RRT:    {"dns_rrt_sum", "累计所有DNS请求响应时延(us)"},
			LATENCY_MYSQL_RRT:  {"mysql_rrt_sum", "累计所有MYSQL请求响应时延(us)"},
			LATENCY_REDIS_RRT:  {"redis_rrt_sum", "累计所有REDIS请求响应时延(us)"},
		},
		ckdb.Float64)
	counterColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			LATENCY_RTT:        {"rtt_count", "建立连接时延计算次数"},
			LATENCY_RTT_CLIENT: {"rtt_client_count", "客户端建立连接时延计算次数"},
			LATENCY_RTT_SERVER: {"rtt_server_count", "服务端建立连接时延计算次数"},
			LATENCY_SRT:        {"srt_count", "系统响应时延计算次数"},
			LATENCY_ART:        {"art_count", "应用响应时延计算次数"},
			LATENCY_HTTP_RRT:   {"http_rrt_count", "HTTP请求响应时延计算次数"},
			LATENCY_DNS_RRT:    {"dns_rrt_count", "DNS请求响应时延计算次数"},
			LATENCY_MYSQL_RRT:  {"mysql_rrt_count", "MYSQL请求响应时延计算次数"},
			LATENCY_REDIS_RRT:  {"redis_rrt_count", "REDIS请求响应时延计算次数"},
		},
		ckdb.UInt64)
	maxColumns := ckdb.NewColumnsWithComment(
		[][2]string{
			LATENCY_RTT:        {"rtt_max", "建立连接RTT最大值(us)"},
			LATENCY_RTT_CLIENT: {"rtt_client_max", "客户端建立连接RTT最大值(us)"},
			LATENCY_RTT_SERVER: {"rtt_server_max", "服务端建立连接RTT最大值(us)"},
			LATENCY_SRT:        {"srt_max", "所有系统响应时延最大值(us)"},
			LATENCY_ART:        {"art_max", "所有应用响应时延最大值(us)"},
			LATENCY_HTTP_RRT:   {"http_rrt_max", "所有HTTP请求响应时延最大值(us)"},
			LATENCY_DNS_RRT:    {"dns_rrt_max", "所有DNS请求响应时延最大值(us)"},
			LATENCY_MYSQL_RRT:  {"mysql_rrt_max", "所有MYSQL请求响应时延最大值(us)"},
			LATENCY_REDIS_RRT:  {"redis_rrt_max", "所有REDIS请求响应时延最大值(us)"},
		}, ckdb.UInt32)
	for _, c := range maxColumns {
		c.SetIndex(ckdb.IndexNone)
	}
	columns := []*ckdb.Column{}
	columns = append(columns, sumColumns...)
	columns = append(columns, counterColumns...)
	columns = append(columns, maxColumns...)
	return columns
}

// WriteBlock和LatencyColumns的列需要按顺序一一对应
func (l *Latency) WriteBlock(block *ckdb.Block) error {
	sumValues := []float64{
		LATENCY_RTT:        float64(l.RTTSum),
		LATENCY_RTT_CLIENT: float64(l.RTTClientSum),
		LATENCY_RTT_SERVER: float64(l.RTTServerSum),
		LATENCY_SRT:        float64(l.SRTSum),
		LATENCY_ART:        float64(l.ARTSum),
		LATENCY_HTTP_RRT:   float64(l.HTTPRRTSum),
		LATENCY_DNS_RRT:    float64(l.DNSRRTSum),
		LATENCY_MYSQL_RRT:  float64(l.MYSQLRRTSum),
		LATENCY_REDIS_RRT:  float64(l.REDISRRTSum)}
	counterValues := []uint64{
		LATENCY_RTT:        uint64(l.RTTCount),
		LATENCY_RTT_CLIENT: uint64(l.RTTClientCount),
		LATENCY_RTT_SERVER: uint64(l.RTTServerCount),
		LATENCY_SRT:        uint64(l.SRTCount),
		LATENCY_ART:        uint64(l.ARTCount),
		LATENCY_HTTP_RRT:   uint64(l.HTTPRRTCount),
		LATENCY_DNS_RRT:    uint64(l.DNSRRTCount),
		LATENCY_MYSQL_RRT:  uint64(l.MYSQLRRTCount),
		LATENCY_REDIS_RRT:  uint64(l.REDISRRTCount)}
	maxValues := []uint32{
		LATENCY_RTT:        l.RTTMax,
		LATENCY_RTT_CLIENT: l.RTTClientMax,
		LATENCY_RTT_SERVER: l.RTTServerMax,
		LATENCY_SRT:        l.SRTMax,
		LATENCY_ART:        l.ARTMax,
		LATENCY_HTTP_RRT:   l.HTTPRRTMax,
		LATENCY_DNS_RRT:    l.DNSRRTMax,
		LATENCY_MYSQL_RRT:  l.MYSQLRRTMax,
		LATENCY_REDIS_RRT:  l.REDISRRTMax}
	for _, v := range sumValues {
		if err := block.WriteFloat64(v); err != nil {
			return err
		}
	}

	for _, v := range counterValues {
		if err := block.WriteUInt64(v); err != nil {
			return err
		}
	}

	for _, v := range maxValues {
		if err := block.WriteUInt32(v); err != nil {
			return err
		}
	}
	return nil
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

const (
	PERF_RETRANS_TX = iota
	PERF_RETRANS_RX
	PERF_RETRANS

	PERF_ZERO_WIN_TX
	PERF_ZERO_WIN_RX
	PERF_ZERO_WIN
)

// Columns列和WriteBlock的列需要按顺序一一对应
func PerformanceColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment(
		[][2]string{
			PERF_RETRANS_TX: {"retrans_tx", "客户端累计重传次数"},
			PERF_RETRANS_RX: {"retrans_rx", "服务端累计重传次数"},
			PERF_RETRANS:    {"retrans", "累计重传次数"},

			PERF_ZERO_WIN_TX: {"zero_win_tx", "客户端累计零窗次数"},
			PERF_ZERO_WIN_RX: {"zero_win_rx", "服务端累计零窗次数"},
			PERF_ZERO_WIN:    {"zero_win", "累计零窗次数"},
		},
		ckdb.UInt64)
}

// WriteBlock的列和PerformanceColumns需要按顺序一一对应
func (a *Performance) WriteBlock(block *ckdb.Block) error {
	values := []uint64{
		a.RetransTx, a.RetransRx, a.RetransTx + a.RetransRx,
		a.ZeroWinTx, a.ZeroWinRx, a.ZeroWinTx + a.ZeroWinRx,
	}
	for _, v := range values {
		if err := block.WriteUInt64(v); err != nil {
			return err
		}
	}
	return nil
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

	HTTPClientError  uint32 `db:"http_client_error"`
	HTTPServerError  uint32 `db:"http_server_error"`
	HTTPTimeout      uint32 `db:"http_timeout"`
	DNSClientError   uint32 `db:"dns_client_error"`
	DNSServerError   uint32 `db:"dns_server_error"`
	DNSTimeout       uint32 `db:"dns_timeout"`
	MYSQLClientError uint32 `db:"mysql_client_error"`
	MYSQLServerError uint32 `db:"mysql_server_error"`
	MYSQLTimeout     uint32 `db:"mysql_timeout"`
	REDISClientError uint32 `db:"redis_client_error"`
	REDISServerError uint32 `db:"redis_server_error"`
	REDISTimeout     uint32 `db:"redis_timeout"`
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

	encoder.WriteVarintU32(a.HTTPClientError)
	encoder.WriteVarintU32(a.HTTPServerError)
	encoder.WriteVarintU32(a.HTTPTimeout)
	encoder.WriteVarintU32(a.DNSClientError)
	encoder.WriteVarintU32(a.DNSServerError)
	encoder.WriteVarintU32(a.DNSTimeout)
	encoder.WriteVarintU32(a.MYSQLClientError)
	encoder.WriteVarintU32(a.MYSQLServerError)
	encoder.WriteVarintU32(a.MYSQLTimeout)
	encoder.WriteVarintU32(a.REDISClientError)
	encoder.WriteVarintU32(a.REDISServerError)
	encoder.WriteVarintU32(a.REDISTimeout)
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

	a.HTTPClientError = decoder.ReadVarintU32()
	a.HTTPServerError = decoder.ReadVarintU32()
	a.HTTPTimeout = decoder.ReadVarintU32()
	a.DNSClientError = decoder.ReadVarintU32()
	a.DNSServerError = decoder.ReadVarintU32()
	a.DNSTimeout = decoder.ReadVarintU32()
	a.MYSQLClientError = decoder.ReadVarintU32()
	a.MYSQLServerError = decoder.ReadVarintU32()
	a.MYSQLTimeout = decoder.ReadVarintU32()
	a.REDISClientError = decoder.ReadVarintU32()
	a.REDISServerError = decoder.ReadVarintU32()
	a.REDISTimeout = decoder.ReadVarintU32()
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

	a.MYSQLClientError += other.MYSQLClientError
	a.MYSQLServerError += other.MYSQLServerError
	a.MYSQLTimeout += other.MYSQLTimeout

	a.REDISClientError += other.REDISClientError
	a.REDISServerError += other.REDISServerError
	a.REDISTimeout += other.REDISTimeout
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
		"mysql_client_error=", "mysql_server_error=", "mysql_timeout=", "mysql_error=",
		"redis_client_error=", "redis_server_error=", "redis_timeout=", "redis_error=",
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
		uint64(a.HTTPClientError), uint64(a.HTTPServerError), uint64(a.HTTPTimeout), uint64(a.HTTPClientError + a.HTTPServerError),
		uint64(a.DNSClientError), uint64(a.DNSServerError), uint64(a.DNSTimeout), uint64(a.DNSClientError + a.DNSServerError),
		uint64(a.MYSQLClientError), uint64(a.MYSQLServerError), uint64(a.MYSQLTimeout), uint64(a.MYSQLClientError + a.MYSQLServerError),
		uint64(a.REDISClientError), uint64(a.REDISServerError), uint64(a.REDISTimeout), uint64(a.REDISClientError + a.REDISServerError),
	}
	return marshalKeyValues(b, fields, values)
}

const (
	ANOMALY_CLIENT_RST_FLOW = iota
	ANOMALY_SERVER_RST_FLOW

	ANOMALY_CLIENT_SYN_REPEAT
	ANOMALY_SERVER_SYN_ACK_REPEAT

	ANOMALY_CLIENT_HALF_CLOSE_FLOW
	ANOMALY_SERVER_HALF_CLOSE_FLOW

	ANOMALY_CLIENT_SOURCE_PORT_REUSE
	ANOMALY_SERVER_RESET
	ANOMALY_SERVER_QUEUE_LACK

	ANOMALY_CLIENT_ESTABLISH_OTHER_RST
	ANOMALY_SERVER_ESTABLISH_OTHER_RST

	ANOMALY_TCP_TIMEOUT

	ANOMALY_CLIENT_ESTABLISH_FAIL
	ANOMALY_SERVER_ESTABLISH_FAIL
	ANOMALY_TCP_ESTABLISH_FAIL

	ANOMALY_HTTP_CLIENT_ERROR
	ANOMALY_HTTP_SERVER_ERROR
	ANOMALY_HTTP_TIMEOUT
	ANOMALY_HTTP_ERROR

	ANOMALY_DNS_CLIENT_ERROR
	ANOMALY_DNS_SERVER_ERROR
	ANOMALY_DNS_TIMEOUT
	ANOMALY_DNS_ERROR

	ANOMALY_MYSQL_CLIENT_ERROR
	ANOMALY_MYSQL_SERVER_ERROR
	ANOMALY_MYSQL_TIMEOUT
	ANOMALY_MYSQL_ERROR

	ANOMALY_REDIS_CLIENT_ERROR
	ANOMALY_REDIS_SERVER_ERROR
	ANOMALY_REDIS_TIMEOUT
	ANOMALY_REDIS_ERROR
)

// Columns列和WriteBlock的列需要按顺序一一对应
func AnomalyColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment(
		[][2]string{
			ANOMALY_CLIENT_RST_FLOW: {"client_rst_flow", "传输-客户端重置"},
			ANOMALY_SERVER_RST_FLOW: {"server_rst_flow", "传输-服务端重置"},

			ANOMALY_CLIENT_SYN_REPEAT:     {"client_syn_repeat", "建连-客户端SYN结束"},
			ANOMALY_SERVER_SYN_ACK_REPEAT: {"server_syn_ack_repeat", "建连-服务端SYN结束"},

			ANOMALY_CLIENT_HALF_CLOSE_FLOW: {"client_half_close_flow", "断连-客户端半关"},
			ANOMALY_SERVER_HALF_CLOSE_FLOW: {"server_half_close_flow", "断连-服务端半关"},

			ANOMALY_CLIENT_SOURCE_PORT_REUSE: {"client_source_port_reuse", "建连-客户端端口复用"},
			ANOMALY_SERVER_RESET:             {"server_reset", "建连-服务端直接重置"},
			ANOMALY_SERVER_QUEUE_LACK:        {"server_queue_lack", "传输-服务端队列溢出"},

			ANOMALY_CLIENT_ESTABLISH_OTHER_RST: {"client_establish_other_rst", "建连-客户端其他重置"},
			ANOMALY_SERVER_ESTABLISH_OTHER_RST: {"server_establish_other_rst", "建连-服务端其他重置"},

			ANOMALY_TCP_TIMEOUT: {"tcp_timeout", "TCP连接超时次数"},

			ANOMALY_CLIENT_ESTABLISH_FAIL: {"client_establish_fail", "TCP客户端建连失败次数"},
			ANOMALY_SERVER_ESTABLISH_FAIL: {"server_establish_fail", "TCP服务端建连失败次数"},
			ANOMALY_TCP_ESTABLISH_FAIL:    {"tcp_establish_fail", "TCP建连失败次数"},

			ANOMALY_HTTP_CLIENT_ERROR: {"http_client_error", "HTTP客户端异常次数"},
			ANOMALY_HTTP_SERVER_ERROR: {"http_server_error", "HTTP服务端异常次数"},
			ANOMALY_HTTP_TIMEOUT:      {"http_timeout", "HTTP请求超时次数"},
			ANOMALY_HTTP_ERROR:        {"http_error", "HTTP异常次数"},

			ANOMALY_DNS_CLIENT_ERROR: {"dns_client_error", "DNS客户端错误次数"},
			ANOMALY_DNS_SERVER_ERROR: {"dns_server_error", "DNS服务端错误次数"},
			ANOMALY_DNS_TIMEOUT:      {"dns_timeout", "DNS请求超时次数"},
			ANOMALY_DNS_ERROR:        {"dns_error", "DNS异常次数"},

			ANOMALY_MYSQL_CLIENT_ERROR: {"mysql_client_error", "MYSQL客户端错误次数"},
			ANOMALY_MYSQL_SERVER_ERROR: {"mysql_server_error", "MYSQL服务端错误次数"},
			ANOMALY_MYSQL_TIMEOUT:      {"mysql_timeout", "MYSQL请求超时次数"},
			ANOMALY_MYSQL_ERROR:        {"mysql_error", "MYSQL异常次数"},

			ANOMALY_REDIS_CLIENT_ERROR: {"redis_client_error", "REDIS客户端错误次数"},
			ANOMALY_REDIS_SERVER_ERROR: {"redis_server_error", "REDIS服务端错误次数"},
			ANOMALY_REDIS_TIMEOUT:      {"redis_timeout", "REDIS请求超时次数"},
			ANOMALY_REDIS_ERROR:        {"redis_error", "REDIS异常次数"},
		}, ckdb.UInt64)
}

// WriteBlock的列和AnomalyColumns需要按顺序一一对应
func (a *Anomaly) WriteBlock(block *ckdb.Block) error {
	clientFail := a.ClientSynRepeat + a.ClientSourcePortReuse + a.ClientEstablishReset
	serverFail := a.ServerSYNACKRepeat + a.ServerReset + a.ServerQueueLack + a.ServerEstablishReset
	values := []uint64{
		ANOMALY_CLIENT_RST_FLOW: a.ClientRstFlow,
		ANOMALY_SERVER_RST_FLOW: a.ServerRstFlow,

		ANOMALY_CLIENT_SYN_REPEAT:     a.ClientSynRepeat,
		ANOMALY_SERVER_SYN_ACK_REPEAT: a.ServerSYNACKRepeat,

		ANOMALY_CLIENT_HALF_CLOSE_FLOW: a.ClientHalfCloseFlow,
		ANOMALY_SERVER_HALF_CLOSE_FLOW: a.ServerHalfCloseFlow,

		ANOMALY_CLIENT_SOURCE_PORT_REUSE: a.ClientSourcePortReuse,
		ANOMALY_SERVER_RESET:             a.ServerReset,
		ANOMALY_SERVER_QUEUE_LACK:        a.ServerQueueLack,

		ANOMALY_CLIENT_ESTABLISH_OTHER_RST: a.ClientEstablishReset,
		ANOMALY_SERVER_ESTABLISH_OTHER_RST: a.ServerEstablishReset,

		ANOMALY_TCP_TIMEOUT: a.TCPTimeout,

		ANOMALY_CLIENT_ESTABLISH_FAIL: clientFail,
		ANOMALY_SERVER_ESTABLISH_FAIL: serverFail,
		ANOMALY_TCP_ESTABLISH_FAIL:    clientFail + serverFail,

		ANOMALY_HTTP_CLIENT_ERROR: uint64(a.HTTPClientError),
		ANOMALY_HTTP_SERVER_ERROR: uint64(a.HTTPServerError),
		ANOMALY_HTTP_TIMEOUT:      uint64(a.HTTPTimeout),
		ANOMALY_HTTP_ERROR:        uint64(a.HTTPClientError + a.HTTPServerError),

		ANOMALY_DNS_CLIENT_ERROR: uint64(a.DNSClientError),
		ANOMALY_DNS_SERVER_ERROR: uint64(a.DNSServerError),
		ANOMALY_DNS_TIMEOUT:      uint64(a.DNSTimeout),
		ANOMALY_DNS_ERROR:        uint64(a.DNSClientError + a.DNSServerError),

		ANOMALY_MYSQL_CLIENT_ERROR: uint64(a.MYSQLClientError),
		ANOMALY_MYSQL_SERVER_ERROR: uint64(a.MYSQLServerError),
		ANOMALY_MYSQL_TIMEOUT:      uint64(a.MYSQLTimeout),
		ANOMALY_MYSQL_ERROR:        uint64(a.MYSQLClientError + a.MYSQLServerError),

		ANOMALY_REDIS_CLIENT_ERROR: uint64(a.REDISClientError),
		ANOMALY_REDIS_SERVER_ERROR: uint64(a.REDISServerError),
		ANOMALY_REDIS_TIMEOUT:      uint64(a.REDISTimeout),
		ANOMALY_REDIS_ERROR:        uint64(a.REDISClientError + a.REDISServerError),
	}
	for _, v := range values {
		if err := block.WriteUInt64(v); err != nil {
			return err
		}
	}
	return nil
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

const (
	FLOW_LOAD = iota
)

func FlowLoadColumns() []*ckdb.Column {
	return ckdb.NewColumnsWithComment([][2]string{FLOW_LOAD: {"flow_load", "累计活跃连接数"}}, ckdb.UInt64)
}

func (l *FlowLoad) WriteBlock(block *ckdb.Block) error {
	values := []uint64{
		FLOW_LOAD: l.Load,
	}
	for _, v := range values {
		if err := block.WriteUInt64(v); err != nil {
			return err
		}
	}
	return nil
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
