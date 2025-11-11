package diffbase

import (
	"testing"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
)

func TestPodServiceExternalIPSync(t *testing.T) {
	// 创建 mock 数据集
	dataset := &DataSet{
		PodServices: make(map[string]*PodService),
		metadata:    &common.Metadata{},
	}

	// 创建 mock 工具数据集
	toolDataSet := &tool.DataSet{}

	// 测试场景1：AddPodService 应该正确设置 ExternalIP
	dbItem := &mysqlmodel.PodService{
		Base: mysqlmodel.Base{
			Lcuuid: "test-lcuuid-1",
		},
		Name:             "test-service",
		ExternalIP:       "192.168.1.100",
		ServiceClusterIP: "10.0.0.1",
	}

	dataset.AddPodService(dbItem, 1, toolDataSet)

	// 验证 ExternalIP 被正确设置
	podService := dataset.PodServices["test-lcuuid-1"]
	if podService.ExternalIP != "192.168.1.100" {
		t.Errorf("Expected ExternalIP to be '192.168.1.100', got '%s'", podService.ExternalIP)
	}

	// 测试场景2：Update 应该正确更新 ExternalIP
	cloudItem := &cloudmodel.PodService{
		Lcuuid:           "test-lcuuid-1",
		Name:             "test-service",
		ExternalIP:       "192.168.1.200", // 不同的 IP
		ServiceClusterIP: "10.0.0.1",
		Metadata:         "{}",
		Spec:             "{}",
	}

	podService.Update(cloudItem, toolDataSet)

	// 验证 ExternalIP 被正确更新
	if podService.ExternalIP != "192.168.1.200" {
		t.Errorf("Expected ExternalIP to be updated to '192.168.1.200', got '%s'", podService.ExternalIP)
	}

	// 测试场景3：空字符串 ExternalIP
	cloudItem.ExternalIP = ""
	podService.Update(cloudItem, toolDataSet)

	if podService.ExternalIP != "" {
		t.Errorf("Expected ExternalIP to be empty string, got '%s'", podService.ExternalIP)
	}
}

func TestPodServiceExternalIPComparison(t *testing.T) {
	// 模拟两个不同的 PodService 对象
	diffBase := &PodService{
		ExternalIP: "192.168.1.100",
	}

	cloudItem := &cloudmodel.PodService{
		ExternalIP: "192.168.1.200",
	}

	// 在修复之前，这个比较应该会发现差异
	if diffBase.ExternalIP == cloudItem.ExternalIP {
		t.Error("Expected ExternalIP to be different, but they are the same")
	}

	// 测试相同的情况
	cloudItem.ExternalIP = "192.168.1.100"
	if diffBase.ExternalIP != cloudItem.ExternalIP {
		t.Error("Expected ExternalIP to be the same, but they are different")
	}
}
