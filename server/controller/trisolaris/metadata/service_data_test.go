package metadata

import (
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"

	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbcache"
	. "github.com/deepflowio/deepflow/server/controller/trisolaris/utils"
)

func TestCustomServiceMerging(t *testing.T) {
	// This test will be replaced by TestMergeCustomServices
	t.Skip("This test is replaced by TestMergeCustomServices")
}

func TestGenerateService(t *testing.T) {
	// This test will be replaced by TestMergeCustomServices
	t.Skip("This test is replaced by TestMergeCustomServices")
}

// TestMergeCustomServices tests the mergeCustomServices method
func TestServiceRawData_MergeCustomServices(t *testing.T) {
	// Create test MetaData with mock ORG ID
	md := &MetaData{
		ORGID: ORGID(1),
	}

	// Helper to create a DBDataCache with custom services for testing
	makeDBCache := func(services []*model.CustomService) *dbcache.DBDataCache {
		dbCache := &dbcache.DBDataCache{}
		dbCache.SetCustomServices(services)
		return dbCache
	}

	t.Run("BasicDeduplication", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 1},
				Name:      "service1",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "192.168.1.1:80,192.168.1.2:443",
				VPCIDs:    model.AutoSplitedInts{1},
			},
			{
				Base:      model.Base{ID: 2},
				Name:      "service2",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "192.168.1.1:80,192.168.1.3:80", // 192.168.1.1:80 already exists
				VPCIDs:    model.AutoSplitedInts{1},
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Service 1 should get 192.168.1.1:80 and 192.168.1.2:443
		service1IPs := serviceRawData.customServiceIDToIPPorts[1]
		assert.True(t, service1IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 1}),
			"Service1 missing expected IP:port: 192.168.1.1:80 in VPC 1. Actual: %v", service1IPs.ToSlice())
		assert.True(t, service1IPs.Contains(customServiceIPPortKey{ip: "192.168.1.2", port: 443, vpcID: 1}),
			"Service1 missing expected IP:port: 192.168.1.2:443 in VPC 1. Actual: %v", service1IPs.ToSlice())
		assert.Equal(t, 2, service1IPs.Cardinality())

		// Service 2 should only get 192.168.1.3:80 (192.168.1.1:80 was already taken)
		service2IPs := serviceRawData.customServiceIDToIPPorts[2]
		assert.True(t, service2IPs.Contains(customServiceIPPortKey{ip: "192.168.1.3", port: 80, vpcID: 1}),
			"Service2 missing expected IP:port: 192.168.1.3:80 in VPC 1. Actual: %v", service2IPs.ToSlice())
		assert.Equal(t, 1, service2IPs.Cardinality())
	})

	t.Run("EmptyPortRule", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 3},
				Name:      "service3",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "192.168.1.1:80,192.168.1.2:443",
				VPCIDs:    model.AutoSplitedInts{1},
			},
			{
				Base:      model.Base{ID: 4},
				Name:      "service4",
				Type:      CUSTOM_SERVICE_TYPE_IP,
				Resources: "192.168.1.1,192.168.1.3", // 192.168.1.1 has empty port
				VPCIDs:    model.AutoSplitedInts{1},
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Service 3 should have one entry for 192.168.1.2 (192.168.1.1:80 dropped due to empty port rule)
		service3IPs := serviceRawData.customServiceIDToIPPorts[3]
		assert.True(t, service3IPs.Contains(customServiceIPPortKey{ip: "192.168.1.2", port: 443, vpcID: 1}),
			"Service3 missing expected IP:port: 192.168.1.2:443 in VPC 1. Actual: %v", service3IPs.ToSlice())
		assert.Equal(t, 1, service3IPs.Cardinality())

		// Service 4 should have two entries for 192.168.1.1 and 192.168.1.3
		service4IPs := serviceRawData.customServiceIDToIPPorts[4]
		assert.True(t, service4IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 0, vpcID: 1}),
			"Service4 missing expected IP with empty port: 192.168.1.1 in VPC 1. Actual: %v", service4IPs.ToSlice())
		assert.True(t, service4IPs.Contains(customServiceIPPortKey{ip: "192.168.1.3", port: 0, vpcID: 1}),
			"Service4 missing expected IP with empty port: 192.168.1.3 in VPC 1. Actual: %v", service4IPs.ToSlice())
		assert.Equal(t, 2, service4IPs.Cardinality())
	})

	t.Run("DifferentVPCs", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 5},
				Name:      "service5",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "192.168.1.1:80",
				VPCIDs:    model.AutoSplitedInts{1},
			},
			{
				Base:      model.Base{ID: 6},
				Name:      "service6",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "192.168.1.1:80", // Same IP:port but different VPC
				VPCIDs:    model.AutoSplitedInts{2},
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Both services should have their entries (different VPCs)
		service5IPs := serviceRawData.customServiceIDToIPPorts[5]
		assert.True(t, service5IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 1}))
		assert.Equal(t, 1, service5IPs.Cardinality())

		service6IPs := serviceRawData.customServiceIDToIPPorts[6]
		assert.True(t, service6IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 2}))
		assert.Equal(t, 1, service6IPs.Cardinality())
	})

	t.Run("EmptyServices", func(t *testing.T) {
		services := []*model.CustomService{}
		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))
		assert.Equal(t, 0, len(serviceRawData.customServiceIDToIPPorts))
	})

	// 新增测试：VPC 为空时匹配所有 VPC
	t.Run("EmptyVPCMatchesAll", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 10},
				Name:      "global-service",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.1:80,10.0.0.2:443",
				VPCIDs:    model.AutoSplitedInts{}, // 空 VPC，匹配所有 VPC
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Service 10 should have entries with vpcID=0 (match all VPCs)
		service10IPs := serviceRawData.customServiceIDToIPPorts[10]
		assert.NotNil(t, service10IPs)
		assert.True(t, service10IPs.Contains(customServiceIPPortKey{ip: "10.0.0.1", port: 80, vpcID: 0}),
			"Global service missing 10.0.0.1:80 with vpcID=0. Actual: %v", service10IPs.ToSlice())
		assert.True(t, service10IPs.Contains(customServiceIPPortKey{ip: "10.0.0.2", port: 443, vpcID: 0}),
			"Global service missing 10.0.0.2:443 with vpcID=0. Actual: %v", service10IPs.ToSlice())
		assert.Equal(t, 2, service10IPs.Cardinality())
	})

	t.Run("EmptyVPCIPType", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 11},
				Name:      "global-ip-service",
				Type:      CUSTOM_SERVICE_TYPE_IP,
				Resources: "10.0.0.1,10.0.0.2",
				VPCIDs:    model.AutoSplitedInts{}, // 空 VPC
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Service 11 should have entries with vpcID=0 and port=0
		service11IPs := serviceRawData.customServiceIDToIPPorts[11]
		assert.NotNil(t, service11IPs)
		assert.True(t, service11IPs.Contains(customServiceIPPortKey{ip: "10.0.0.1", port: 0, vpcID: 0}))
		assert.True(t, service11IPs.Contains(customServiceIPPortKey{ip: "10.0.0.2", port: 0, vpcID: 0}))
		assert.Equal(t, 2, service11IPs.Cardinality())
	})

	// VPC 为空和有 VPC 的服务不互相去重
	t.Run("EmptyVPCDoesNotDeduplicateWithSpecificVPC", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 12},
				Name:      "vpc-specific-service",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.1:80",
				VPCIDs:    model.AutoSplitedInts{1},
			},
			{
				Base:      model.Base{ID: 13},
				Name:      "global-service",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.1:80", // same IP:port but no VPC (global)
				VPCIDs:    model.AutoSplitedInts{},
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Both should exist since vpcID=1 and vpcID=0 are different dedup keys
		service12IPs := serviceRawData.customServiceIDToIPPorts[12]
		assert.NotNil(t, service12IPs)
		assert.True(t, service12IPs.Contains(customServiceIPPortKey{ip: "10.0.0.1", port: 80, vpcID: 1}))
		assert.Equal(t, 1, service12IPs.Cardinality())

		service13IPs := serviceRawData.customServiceIDToIPPorts[13]
		assert.NotNil(t, service13IPs)
		assert.True(t, service13IPs.Contains(customServiceIPPortKey{ip: "10.0.0.1", port: 80, vpcID: 0}))
		assert.Equal(t, 1, service13IPs.Cardinality())
	})

	// VPC 为空的 IP 类型与有 VPC 的 PORT 类型不互相影响空端口规则
	t.Run("EmptyVPCEmptyPortRuleIndependent", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 14},
				Name:      "vpc1-port-service",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.1:80",
				VPCIDs:    model.AutoSplitedInts{1},
			},
			{
				Base:      model.Base{ID: 15},
				Name:      "global-ip-service",
				Type:      CUSTOM_SERVICE_TYPE_IP,
				Resources: "10.0.0.1", // 空端口，但 vpcID=0
				VPCIDs:    model.AutoSplitedInts{},
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Service 14 should keep its 10.0.0.1:80 in VPC 1 (empty port rule only applies within same VPC key scope)
		service14IPs := serviceRawData.customServiceIDToIPPorts[14]
		assert.NotNil(t, service14IPs)
		assert.True(t, service14IPs.Contains(customServiceIPPortKey{ip: "10.0.0.1", port: 80, vpcID: 1}),
			"VPC-specific service should not be affected by global empty port. Actual: %v", service14IPs.ToSlice())
		assert.Equal(t, 1, service14IPs.Cardinality())

		// Service 15 should have the empty port entry with vpcID=0
		service15IPs := serviceRawData.customServiceIDToIPPorts[15]
		assert.NotNil(t, service15IPs)
		assert.True(t, service15IPs.Contains(customServiceIPPortKey{ip: "10.0.0.1", port: 0, vpcID: 0}))
		assert.Equal(t, 1, service15IPs.Cardinality())
	})

	// 多个 VPC 仍然报 warning 并跳过
	t.Run("MultiVPCsStillSkipped", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:      model.Base{ID: 16},
				Name:      "multi-vpc-service",
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.1:80",
				VPCIDs:    model.AutoSplitedInts{1, 2}, // 多个 VPC，应被跳过
			},
		}

		serviceRawData := newServiceRawData()
		serviceRawData.mergeCustomServices(md, makeDBCache(services))

		// Should not have any entries
		_, exists := serviceRawData.customServiceIDToIPPorts[16]
		assert.False(t, exists, "Multi-VPC service should be skipped")
	})
}

// TestServiceDataOP_MergeCustomServices tests the ServiceDataOP.mergeCustomServices method
func TestServiceDataOP_MergeCustomServices(t *testing.T) {
	// Create mock custom services
	customServices := []*model.CustomService{
		{
			Base:      model.Base{ID: 1},
			Name:      "service1",
			VPCIDs:    model.AutoSplitedInts{1},
			Type:      CUSTOM_SERVICE_TYPE_PORT,
			Resources: "192.168.1.1:80",
		},
		{
			Base:      model.Base{ID: 2},
			Name:      "service2",
			VPCIDs:    model.AutoSplitedInts{2},
			Type:      CUSTOM_SERVICE_TYPE_IP,
			Resources: "192.168.1.2",
		},
	}

	// Create a real DBDataCache with our test data
	dbCache := &dbcache.DBDataCache{}
	dbCache.SetCustomServices(customServices)

	// Create ServiceDataOP instance
	s := &ServiceDataOP{
		serviceRawData: newServiceRawData(),
		ORGID:          ORGID(1),
	}

	// Set custom service ID to IP port mappings
	s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{
		1: mapset.NewSet(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 1}),
		2: mapset.NewSet(customServiceIPPortKey{ip: "192.168.1.2", port: 0, vpcID: 2}),
	}

	// Test basic functionality
	t.Run("BasicFunctionality", func(t *testing.T) {
		// Execute test
		result := s.mergeCustomServices(dbCache)

		// Verify results
		assert.Equal(t, 2, len(result))

		// Verify service1 (with port, with VPC)
		var service1Found bool
		var service2Found bool
		for _, svc := range result {
			if *svc.Id == 1 && len(svc.Ips) == 1 && svc.Ips[0] == "192.168.1.1" &&
				len(svc.ServerPorts) == 1 && svc.ServerPorts[0] == 80 &&
				svc.EpcId != nil && *svc.EpcId == 1 {
				service1Found = true
			}
			if *svc.Id == 2 && len(svc.Ips) == 1 && svc.Ips[0] == "192.168.1.2" &&
				len(svc.ServerPorts) == 0 &&
				svc.EpcId != nil && *svc.EpcId == 2 {
				service2Found = true
			}
		}
		assert.True(t, service1Found, "Service 1 not found or incorrect")
		assert.True(t, service2Found, "Service 2 not found or incorrect")
	})

	// Test multiple IP-port combinations for one service
	t.Run("MultipleIPPortCombinations", func(t *testing.T) {
		// Update custom services
		dbCache.SetCustomServices([]*model.CustomService{
			{
				Base:      model.Base{ID: 3},
				Name:      "service3",
				VPCIDs:    model.AutoSplitedInts{1},
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "192.168.1.10:80,192.168.1.10:443",
			},
		})

		// Set new mapping
		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{
			3: mapset.NewSet(
				customServiceIPPortKey{ip: "192.168.1.10", port: 80, vpcID: 1},
				customServiceIPPortKey{ip: "192.168.1.10", port: 443, vpcID: 1},
			),
		}

		// Execute test
		result := s.mergeCustomServices(dbCache)

		// Verify results - should have two ServiceInfo objects for the same service ID
		assert.Equal(t, 2, len(result))

		// Check for both ports
		port80Found := false
		port443Found := false
		for _, svc := range result {
			if *svc.Id == 3 && len(svc.ServerPorts) == 1 {
				if svc.ServerPorts[0] == 80 {
					port80Found = true
				} else if svc.ServerPorts[0] == 443 {
					port443Found = true
				}
			}
		}
		assert.True(t, port80Found, "Service with port 80 not found")
		assert.True(t, port443Found, "Service with port 443 not found")
	})

	// Test empty mapping
	t.Run("EmptyMapping", func(t *testing.T) {
		// Update custom services
		dbCache.SetCustomServices([]*model.CustomService{
			{Base: model.Base{ID: 4}, Name: "service4", VPCIDs: model.AutoSplitedInts{1}},
		})

		// Set empty mapping
		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{}

		// Execute test
		result := s.mergeCustomServices(dbCache)

		// Verify results
		assert.Equal(t, 0, len(result))
	})

	// Test ID mismatch
	t.Run("IDMismatch", func(t *testing.T) {
		// Update custom services with ID=5
		dbCache.SetCustomServices([]*model.CustomService{
			{Base: model.Base{ID: 5}, Name: "service5", VPCIDs: model.AutoSplitedInts{1}},
		})

		// Set mapping with ID=6, not 5
		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{
			6: mapset.NewSet(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 1}),
		}

		// Execute test
		result := s.mergeCustomServices(dbCache)

		// Verify results - should be empty due to ID mismatch
		assert.Equal(t, 0, len(result))
	})

	// 新增测试：VPC 为空时 protobuf 输出不设置 EpcId
	t.Run("EmptyVPCProtoNoEpcId", func(t *testing.T) {
		dbCache.SetCustomServices([]*model.CustomService{
			{
				Base:      model.Base{ID: 20},
				Name:      "global-service",
				VPCIDs:    model.AutoSplitedInts{},
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.1:80",
			},
		})

		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{
			20: mapset.NewSet(customServiceIPPortKey{ip: "10.0.0.1", port: 80, vpcID: 0}),
		}

		result := s.mergeCustomServices(dbCache)

		assert.Equal(t, 1, len(result))
		svc := result[0]
		assert.Equal(t, uint32(20), *svc.Id)
		assert.Equal(t, []string{"10.0.0.1"}, svc.Ips)
		assert.Equal(t, []uint32{80}, svc.ServerPorts)
		// vpcID=0 时 EpcId 应为 nil
		assert.Nil(t, svc.EpcId, "EpcId should be nil for global service (empty VPC)")
	})

	// 新增测试：VPC 有值时 protobuf 输出正常设置 EpcId
	t.Run("SpecificVPCProtoHasEpcId", func(t *testing.T) {
		dbCache.SetCustomServices([]*model.CustomService{
			{
				Base:      model.Base{ID: 21},
				Name:      "vpc-service",
				VPCIDs:    model.AutoSplitedInts{5},
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.1:80",
			},
		})

		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{
			21: mapset.NewSet(customServiceIPPortKey{ip: "10.0.0.1", port: 80, vpcID: 5}),
		}

		result := s.mergeCustomServices(dbCache)

		assert.Equal(t, 1, len(result))
		svc := result[0]
		assert.Equal(t, uint32(21), *svc.Id)
		assert.NotNil(t, svc.EpcId, "EpcId should be set for VPC-specific service")
		assert.Equal(t, uint32(5), *svc.EpcId)
	})

	// 新增测试：混合场景 - 同时有空 VPC 和有 VPC 的服务
	t.Run("MixedVPCAndGlobalProto", func(t *testing.T) {
		dbCache.SetCustomServices([]*model.CustomService{
			{
				Base:      model.Base{ID: 22},
				Name:      "global-service",
				VPCIDs:    model.AutoSplitedInts{},
				Type:      CUSTOM_SERVICE_TYPE_IP,
				Resources: "10.0.0.1",
			},
			{
				Base:      model.Base{ID: 23},
				Name:      "vpc-service",
				VPCIDs:    model.AutoSplitedInts{3},
				Type:      CUSTOM_SERVICE_TYPE_PORT,
				Resources: "10.0.0.2:443",
			},
		})

		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{
			22: mapset.NewSet(customServiceIPPortKey{ip: "10.0.0.1", port: 0, vpcID: 0}),
			23: mapset.NewSet(customServiceIPPortKey{ip: "10.0.0.2", port: 443, vpcID: 3}),
		}

		result := s.mergeCustomServices(dbCache)

		assert.Equal(t, 2, len(result))

		var globalFound, vpcFound bool
		for _, svc := range result {
			if *svc.Id == 22 {
				assert.Nil(t, svc.EpcId, "Global service EpcId should be nil")
				assert.Equal(t, []string{"10.0.0.1"}, svc.Ips)
				assert.Equal(t, 0, len(svc.ServerPorts))
				globalFound = true
			}
			if *svc.Id == 23 {
				assert.NotNil(t, svc.EpcId, "VPC service EpcId should not be nil")
				assert.Equal(t, uint32(3), *svc.EpcId)
				assert.Equal(t, []string{"10.0.0.2"}, svc.Ips)
				assert.Equal(t, []uint32{443}, svc.ServerPorts)
				vpcFound = true
			}
		}
		assert.True(t, globalFound, "Global service not found")
		assert.True(t, vpcFound, "VPC service not found")
	})
}
