package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type RedisInstance struct {
	OperatorBase[mysql.RedisInstance]
}

func NewRedisInstance() *RedisInstance {
	operater := &RedisInstance{
		OperatorBase[mysql.RedisInstance]{
			resourceTypeName: common.RESOURCE_TYPE_REDIS_INSTANCE_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *RedisInstance) setDBItemID(dbItem *mysql.RedisInstance, id int) {
	dbItem.ID = id
}
