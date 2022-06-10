package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBRedisInstance() *mysql.RedisInstance {
	return &mysql.RedisInstance{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddRedisInstanceBatchSuccess() {
	operator := NewRedisInstance()
	itemToAdd := newDBRedisInstance()

	_, ok := operator.AddBatch([]*mysql.RedisInstance{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.RedisInstance
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RedisInstance{})
}

func (t *SuiteTest) TestUpdateRedisInstanceSuccess() {
	operator := NewRedisInstance()
	addedItem := newDBRedisInstance()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.RedisInstance
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RedisInstance{})
}

func (t *SuiteTest) TestDeleteRedisInstanceBatchSuccess() {
	operator := NewRedisInstance()
	addedItem := newDBRedisInstance()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.RedisInstance
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
