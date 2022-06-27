package updater

import (
	"math/rand"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
)

func newCloudVPC() cloudmodel.VPC {
	lcuuid := uuid.New().String()
	return cloudmodel.VPC{
		Lcuuid:   lcuuid,
		Name:     lcuuid[:8],
		CIDR:     "1.1.1.0/24",
		TunnelID: rand.Intn(100),
	}
}

func (t *SuiteTest) getVPCMock(mockDB bool) (*cache.Cache, cloudmodel.VPC) {
	cloudItem := newCloudVPC()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.VPC{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.VPCs[cloudItem.Lcuuid] = &cache.VPC{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddVPCSucess() {
	cache, cloudItem := t.getVPCMock(false)
	assert.Equal(t.T(), len(cache.VPCs), 0)

	updater := NewVPC(cache, []cloudmodel.VPC{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.VPC
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.VPCs), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VPC{})
}

func (t *SuiteTest) TestHandleUpdateVPCSucess() {
	cache, cloudItem := t.getVPCMock(true)
	cloudItem.Name = cloudItem.Name + "new"
	cloudItem.CIDR = cloudItem.CIDR + "new"
	cloudItem.TunnelID = cloudItem.TunnelID + 1

	updater := NewVPC(cache, []cloudmodel.VPC{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.VPC
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.VPCs), 1)
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), addedItem.CIDR, cloudItem.CIDR)
	assert.Equal(t.T(), addedItem.TunnelID, cloudItem.TunnelID)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VPC{})
}

func (t *SuiteTest) TestHandleDeleteVPCSucess() {
	cache, cloudItem := t.getVPCMock(true)

	updater := NewVPC(cache, []cloudmodel.VPC{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.VPC
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.VPCs), 0)
}
