package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"server/controller/db/mysql"
)

func newDBPodIngressRule() *mysql.PodIngressRule {
	return &mysql.PodIngressRule{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddPodIngressRuleBatchSuccess() {
	operator := NewPodIngressRule()
	itemToAdd := newDBPodIngressRule()

	_, ok := operator.AddBatch([]*mysql.PodIngressRule{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.PodIngressRule
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodIngressRule{})
}

func (t *SuiteTest) TestDeletePodIngressRuleBatchSuccess() {
	operator := NewPodIngressRule()
	addedItem := newDBPodIngressRule()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.PodIngressRule
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
