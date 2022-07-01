package updater

import (
	"reflect"

	"bou.ke/monkey"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cloudmodel "github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/cache"
	"github.com/metaflowys/metaflow/server/controller/recorder/test"
)

func newCloudPod() cloudmodel.Pod {
	lcuuid := uuid.New().String()
	return cloudmodel.Pod{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
		Label:  lcuuid[:6],
	}
}

func (t *SuiteTest) getPodMock(mockDB bool) (*cache.Cache, cloudmodel.Pod) {
	cloudItem := newCloudPod()
	domainLcuuid := uuid.New().String()

	c := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.Pod{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid, Label: cloudItem.Label})
		c.Pods[cloudItem.Lcuuid] = &cache.Pod{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name, Label: cloudItem.Label}
	}

	c.SetSequence(c.GetSequence() + 1)

	return c, cloudItem
}

func (t *SuiteTest) TestHandleAddPodSucess() {
	c, cloudItem := t.getPodMock(false)
	assert.Equal(t.T(), len(c.Pods), 0)
	vpcID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetVPCIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return vpcID, true
	})
	podNodeID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNodeIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return podNodeID, true
	})
	podNamespaceID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNamespaceIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return podNamespaceID, true
	})
	podClusterID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodClusterIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return podClusterID, true
	})
	podGroupID := randID()
	monkey.PatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodGroupIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return podGroupID, true
	})

	updater := NewPod(c, []cloudmodel.Pod{cloudItem})
	updater.HandleAddAndUpdate()

	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetVPCIDByLcuuid")
	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNodeIDByLcuuid")
	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNamespaceIDByLcuuid")
	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodClusterIDByLcuuid")
	monkey.UnpatchInstanceMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodGroupIDByLcuuid")

	var addedItem *mysql.Pod
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(c.Pods), 1)
	assert.Equal(t.T(), cloudItem.Label, addedItem.Label)

	test.ClearDBData[mysql.Pod](t.db)
}

func (t *SuiteTest) TestHandleUpdatePodSucess() {
	cache, cloudItem := t.getPodMock(true)
	cloudItem.Name = cloudItem.Name + "new"
	cloudItem.Label = cloudItem.Label + "new"

	updater := NewPod(cache, []cloudmodel.Pod{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Pod
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.Pods), 1)
	assert.Equal(t.T(), addedItem.Label, cloudItem.Label)

	test.ClearDBData[mysql.Pod](t.db)
}
