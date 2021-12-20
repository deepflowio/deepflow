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
