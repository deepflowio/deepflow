package pb

import (
	"gitlab.yunshan.net/yunshan/droplet-libs/pool"
)

var pbAppProtoLogsDataPool = pool.NewLockFreePool(func() interface{} {
	return &AppProtoLogsData{
		BaseInfo: &AppProtoLogsBaseInfo{
			Head: &AppProtoHead{},
		},
		Http:  &HTTPInfo{},
		Dns:   &DNSInfo{},
		Dubbo: &DubboInfo{},
		Kafka: &KafkaInfo{},
		Mysql: &MysqlInfo{},
		Redis: &RedisInfo{},
		Mqtt:  &MqttInfo{},
	}
})

func AcquirePbAppProtoLogsData() *AppProtoLogsData {
	d := pbAppProtoLogsDataPool.Get().(*AppProtoLogsData)
	return d
}

func ReleasePbAppProtoLogsData(d *AppProtoLogsData) {
	if d == nil {
		return
	}

	head := d.BaseInfo.Head
	head.Reset()
	basicInfo := d.BaseInfo
	basicInfo.Reset()
	basicInfo.Head = head

	http, dns, dubbo, kafka, mysql, redis, mqtt := d.Http, d.Dns, d.Dubbo, d.Kafka, d.Mysql, d.Redis, d.Mqtt
	http.Reset()
	dns.Reset()
	dubbo.Reset()
	kafka.Reset()
	mysql.Reset()
	redis.Reset()
	mqtt.Reset()

	d.Reset()
	d.BaseInfo = basicInfo
	d.Http, d.Dns, d.Dubbo, d.Kafka, d.Mysql, d.Redis, d.Mqtt = http, dns, dubbo, kafka, mysql, redis, mqtt

	pbAppProtoLogsDataPool.Put(d)
}

func (d *AppProtoLogsData) Release() {
	ReleasePbAppProtoLogsData(d)
}

func (d *AppProtoLogsData) IsValid() bool {
	if d == nil ||
		d.BaseInfo == nil ||
		d.BaseInfo.Head == nil {
		return false
	}
	return true
}

func (t *TaggedFlow) IsValid() bool {
	if t == nil ||
		t.Flow == nil ||
		t.Flow.FlowKey == nil ||
		t.Flow.FlowMetricsPeerSrc == nil ||
		t.Flow.FlowMetricsPeerDst == nil ||
		t.Flow.Tunnel == nil {
		return false
	}
	return true
}

func NewTaggedFlow() *TaggedFlow {
	return &TaggedFlow{
		Flow: &Flow{
			FlowKey:            &FlowKey{},
			FlowMetricsPeerSrc: &FlowMetricsPeer{},
			FlowMetricsPeerDst: &FlowMetricsPeer{},
			Tunnel:             &TunnelField{},
			FlowPerfStats: &FlowPerfStats{
				TCPPerfStats: &TCPPerfStats{
					TcpPerfCountsPeerTx: &TcpPerfCountsPeer{},
					TcpPerfCountsPeerRx: &TcpPerfCountsPeer{},
				},
				L7PerfStats: &L7PerfStats{},
			},
		},
	}
}

// 清空pb的TaggedFlow 使解码时可以反复使用
func (t *TaggedFlow) ResetAll() {
	flowPerfStats := t.Flow.FlowPerfStats
	if flowPerfStats != nil {
		tcpPerfStats := flowPerfStats.TCPPerfStats
		tcpPerfCountsPeerTx := tcpPerfStats.TcpPerfCountsPeerTx
		tcpPerfCountsPeerRx := tcpPerfStats.TcpPerfCountsPeerRx

		tcpPerfCountsPeerTx.Reset()
		tcpPerfCountsPeerRx.Reset()
		tcpPerfStats.Reset()
		tcpPerfStats.TcpPerfCountsPeerTx = tcpPerfCountsPeerTx
		tcpPerfStats.TcpPerfCountsPeerRx = tcpPerfCountsPeerRx

		l7PerfStats := flowPerfStats.L7PerfStats
		l7PerfStats.Reset()

		flowPerfStats.Reset()
		flowPerfStats.L7PerfStats = l7PerfStats
		flowPerfStats.TCPPerfStats = tcpPerfStats
	}

	flowKey := t.Flow.FlowKey
	flowKey.Reset()
	flowMetricsPeerSrc := t.Flow.FlowMetricsPeerSrc
	flowMetricsPeerSrc.Reset()
	flowMetricsPeerDst := t.Flow.FlowMetricsPeerDst
	flowMetricsPeerDst.Reset()
	tunnel := t.Flow.Tunnel
	tunnel.Reset()

	flow := t.Flow
	flow.Reset()

	if flowPerfStats != nil {
		flow.FlowPerfStats = flowPerfStats
	}
	flow.FlowKey = flowKey
	flow.FlowMetricsPeerSrc = flowMetricsPeerSrc
	flow.FlowMetricsPeerDst = flowMetricsPeerDst
	flow.Tunnel = tunnel

	t.Reset()
	t.Flow = flow
}
