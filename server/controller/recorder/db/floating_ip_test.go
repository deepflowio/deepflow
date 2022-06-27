package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

func newDBFloatingIP() *mysql.FloatingIP {
	return &mysql.FloatingIP{Base: mysql.Base{Lcuuid: uuid.New().String()}, IP: uuid.New().String(), Region: uuid.New().String()}
}

func (t *SuiteTest) TestAddFloatingIPBatchSuccess() {
	operator := NewFloatingIP()
	itemToAdd := newDBFloatingIP()

	_, ok := operator.AddBatch([]*mysql.FloatingIP{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.FloatingIP
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.IP, itemToAdd.IP)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.FloatingIP{})
}

func (t *SuiteTest) TestUpdateFloatingIPSuccess() {
	operator := NewFloatingIP()
	addedItem := newDBFloatingIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"region": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.FloatingIP
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Region, updateInfo["region"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.FloatingIP{})
}

func (t *SuiteTest) TestDeleteFloatingIPBatchSuccess() {
	operator := NewFloatingIP()
	addedItem := newDBFloatingIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.FloatingIP
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
