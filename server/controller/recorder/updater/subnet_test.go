package updater

import (
	"reflect"

	"bou.ke/monkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
)

func newCloudSubnet() cloudmodel.Subnet {
	lcuuid := uuid.New().String()
	return cloudmodel.Subnet{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
		CIDR:   "108.0.0.0/16",
	}
}

func (t *SuiteTest) getSubnetMock(mockDB bool) (*cache.Cache, cloudmodel.Subnet) {
	cloudItem := newCloudSubnet()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.Subnet{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}})
		cache_.Subnets[cloudItem.Lcuuid] = &cache.Subnet{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddSubnetSucess() {
	cache_, cloudItem := t.getSubnetMock(false)
	networkID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetNetworkIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return networkID, true
	})
	assert.Equal(t.T(), len(cache_.Subnets), 0)

	updater := NewSubnet(cache_, []cloudmodel.Subnet{cloudItem})
	updater.HandleAddAndUpdate()

	monkey.UnpatchInstanceMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetNetworkIDByLcuuid")

	var addedItem *mysql.Subnet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), int64(1), result.RowsAffected)
	assert.Equal(t.T(), 1, len(cache_.Subnets))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Subnet{})
}

func (t *SuiteTest) TestHandleUpdateSubnetSucess() {
	cache, cloudItem := t.getSubnetMock(true)
	cloudItem.Name = cloudItem.Name + "new"

	updater := NewSubnet(cache, []cloudmodel.Subnet{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Subnet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.Subnets), 1)
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Subnet{})
}

func (t *SuiteTest) TestHandleDeleteSubnetSucess() {
	cache, cloudItem := t.getSubnetMock(true)

	updater := NewSubnet(cache, []cloudmodel.Subnet{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.Subnet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.Subnets), 0)
}
