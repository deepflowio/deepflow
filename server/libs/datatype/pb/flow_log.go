package pb

import (
	"github.com/metaflowys/metaflow/server/libs/pool"
)

var pbAppProtoLogsDataPool = pool.NewLockFreePool(func() interface{} {
	return &AppProtoLogsData{
		Base: &AppProtoLogsBaseInfo{
			Head: &AppProtoHead{},
		},
		Http:  &HttpInfo{},
		Dns:   &DnsInfo{},
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

	head := d.Base.Head
	head.Reset()
	basicInfo := d.Base
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
	d.Base = basicInfo
	d.Http, d.Dns, d.Dubbo, d.Kafka, d.Mysql, d.Redis, d.Mqtt = http, dns, dubbo, kafka, mysql, redis, mqtt

	pbAppProtoLogsDataPool.Put(d)
}

func (d *AppProtoLogsData) Release() {
	ReleasePbAppProtoLogsData(d)
}

func (d *AppProtoLogsData) IsValid() bool {
	if d == nil ||
		d.Base == nil ||
		d.Base.Head == nil {
		return false
	}
	return true
}

func (t *TaggedFlow) IsValid() bool {
	if t == nil ||
		t.Flow == nil ||
		t.Flow.FlowKey == nil ||
		t.Flow.MetricsPeerSrc == nil ||
		t.Flow.MetricsPeerDst == nil ||
		t.Flow.Tunnel == nil {
		return false
	}
	return true
}

func NewTaggedFlow() *TaggedFlow {
	return &TaggedFlow{
		Flow: &Flow{
			FlowKey:        &FlowKey{},
			MetricsPeerSrc: &FlowMetricsPeer{},
			MetricsPeerDst: &FlowMetricsPeer{},
			Tunnel:         &TunnelField{},
			PerfStats: &FlowPerfStats{
				Tcp: &TCPPerfStats{
					CountsPeerTx: &TcpPerfCountsPeer{},
					CountsPeerRx: &TcpPerfCountsPeer{},
				},
				L7: &L7PerfStats{},
			},
		},
	}
}

// 清空pb的TaggedFlow 使解码时可以反复使用
func (t *TaggedFlow) ResetAll() {
	flowPerfStats := t.Flow.PerfStats
	if flowPerfStats != nil {
		tcpPerfStats := flowPerfStats.Tcp
		tcpPerfCountsPeerTx := tcpPerfStats.CountsPeerTx
		tcpPerfCountsPeerRx := tcpPerfStats.CountsPeerRx

		tcpPerfCountsPeerTx.Reset()
		tcpPerfCountsPeerRx.Reset()
		tcpPerfStats.Reset()
		tcpPerfStats.CountsPeerTx = tcpPerfCountsPeerTx
		tcpPerfStats.CountsPeerRx = tcpPerfCountsPeerRx

		l7PerfStats := flowPerfStats.L7
		l7PerfStats.Reset()

		flowPerfStats.Reset()
		flowPerfStats.L7 = l7PerfStats
		flowPerfStats.Tcp = tcpPerfStats
	}

	flowKey := t.Flow.FlowKey
	flowKey.Reset()
	flowMetricsPeerSrc := t.Flow.MetricsPeerSrc
	flowMetricsPeerSrc.Reset()
	flowMetricsPeerDst := t.Flow.MetricsPeerDst
	flowMetricsPeerDst.Reset()
	tunnel := t.Flow.Tunnel
	tunnel.Reset()

	flow := t.Flow
	flow.Reset()

	if flowPerfStats != nil {
		flow.PerfStats = flowPerfStats
	}
	flow.FlowKey = flowKey
	flow.MetricsPeerSrc = flowMetricsPeerSrc
	flow.MetricsPeerDst = flowMetricsPeerDst
	flow.Tunnel = tunnel

	t.Reset()
	t.Flow = flow
}
