package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBWANIP() *mysql.WANIP {
	return &mysql.WANIP{Base: mysql.Base{Lcuuid: uuid.New().String()}, IP: randomIP(), Region: uuid.New().String()}
}

func (t *SuiteTest) TestAddWANIPBatchSuccess() {
	operator := NewWANIP()
	itemToAdd := newDBWANIP()

	_, ok := operator.AddBatch([]*mysql.WANIP{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.WANIP
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.IP, itemToAdd.IP)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.WANIP{})
}

func (t *SuiteTest) TestUpdateWANIPSuccess() {
	operator := NewWANIP()
	addedItem := newDBWANIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"region": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.WANIP
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Region, updateInfo["region"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.WANIP{})
}

func (t *SuiteTest) TestDeleteWANIPBatchSuccess() {
	operator := NewWANIP()
	addedItem := newDBWANIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.WANIP
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
