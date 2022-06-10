package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBPodNode() *mysql.PodNode {
	return &mysql.PodNode{Base: mysql.Base{Lcuuid: uuid.New().String()}, Region: uuid.New().String()}
}

func (t *SuiteTest) TestAddPodNodeBatchSuccess() {
	operator := NewPodNode()
	itemToAdd := newDBPodNode()

	_, ok := operator.AddBatch([]*mysql.PodNode{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.PodNode
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodNode{})
}

func (t *SuiteTest) TestUpdatePodNodeSuccess() {
	operator := NewPodNode()
	addedItem := newDBPodNode()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"region": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.PodNode
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Region, updateInfo["region"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodNode{})
}

func (t *SuiteTest) TestDeletePodNodeBatchSuccess() {
	operator := NewPodNode()
	addedItem := newDBPodNode()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.PodNode
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
