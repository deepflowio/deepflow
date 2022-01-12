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
	}
})

func AcquirePbAppProtoLogsData() *AppProtoLogsData {
	d := pbAppProtoLogsDataPool.Get().(*AppProtoLogsData)
	return d
}

func ReleasePbAppProtoLogsData(d *AppProtoLogsData) {
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
