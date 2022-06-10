package updater

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "server/controller/cloud/model"
	"server/controller/db/mysql"
	"server/controller/recorder/cache"
)

func newCloudSubDomain() cloudmodel.SubDomain {
	lcuuid := uuid.New().String()
	return cloudmodel.SubDomain{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
	}
}

func (t *SuiteTest) getSubDomainMock(mockDB bool) (*cache.Cache, cloudmodel.SubDomain) {
	cloudItem := newCloudSubDomain()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.SubDomain{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.SubDomains[cloudItem.Lcuuid] = &cache.SubDomain{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddSubDomainSucess() {
	cache, cloudItem := t.getSubDomainMock(false)
	assert.Equal(t.T(), len(cache.SubDomains), 0)

	updater := NewSubDomain(cache, []cloudmodel.SubDomain{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.SubDomain
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.SubDomains), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SubDomain{})
}

func (t *SuiteTest) TestHandleDeleteSubDomainSucess() {
	cache, cloudItem := t.getSubDomainMock(true)

	updater := NewSubDomain(cache, []cloudmodel.SubDomain{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.SubDomain
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.SubDomains), 0)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SubDomain{})
}
