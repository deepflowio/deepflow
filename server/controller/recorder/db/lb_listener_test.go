package db

import (
	"math/rand"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

func newDBLBListener() *mysql.LBListener {
	return &mysql.LBListener{Base: mysql.Base{Lcuuid: uuid.New().String()}, Port: rand.Intn(65535)}
}

func (t *SuiteTest) TestAddLBListenerBatchSuccess() {
	operator := NewLBListener()
	itemToAdd := newDBLBListener()

	_, ok := operator.AddBatch([]*mysql.LBListener{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.LBListener
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Port, itemToAdd.Port)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.LBListener{})
}

func (t *SuiteTest) TestUpdateLBListenerSuccess() {
	operator := NewLBListener()
	addedItem := newDBLBListener()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"port": rand.Intn(65535)}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.LBListener
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Port, updateInfo["port"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.LBListener{})
}

func (t *SuiteTest) TestDeleteLBListenerBatchSuccess() {
	operator := NewLBListener()
	addedItem := newDBLBListener()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.LBListener
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
