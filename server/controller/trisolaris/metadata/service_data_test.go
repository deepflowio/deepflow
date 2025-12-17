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

	t.Run("BasicDeduplication", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:     model.Base{ID: 1},
				Name:     "service1",
				Type:     CUSTOM_SERVICE_TYPE_PORT,
				Resource: "192.168.1.1:80,192.168.1.2:443",
				VPCIDs:   1,
			},
			{
				Base:     model.Base{ID: 2},
				Name:     "service2",
				Type:     CUSTOM_SERVICE_TYPE_PORT,
				Resource: "192.168.1.1:80,192.168.1.3:80", // 192.168.1.1:80 already exists
				VPCIDs:   1,
			},
		}

		serviceRawData := newServiceRawData()
		result := serviceRawData.mergeCustomServices(md, services)

		// Service 1 should get 192.168.1.1:80 and 192.168.1.2:443
		service1IPs := result[1]
		if !service1IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 1}) {
			t.Errorf("Service1 missing expected IP:port: 192.168.1.1:80 in VPC 1. Actual: %v", service1IPs.ToSlice())
		}
		if !service1IPs.Contains(customServiceIPPortKey{ip: "192.168.1.2", port: 443, vpcID: 1}) {
			t.Errorf("Service1 missing expected IP:port: 192.168.1.2:443 in VPC 1. Actual: %v", service1IPs.ToSlice())
		}
		if service1IPs.Cardinality() != 2 {
			t.Errorf("Service1 should have exactly 2 IP:port entries. Actual count: %d, Contents: %v",
				service1IPs.Cardinality(), service1IPs.ToSlice())
		}

		// Service 2 should only get 192.168.1.3:80 (192.168.1.1:80 was already taken)
		service2IPs := result[2]
		if !service2IPs.Contains(customServiceIPPortKey{ip: "192.168.1.3", port: 80, vpcID: 1}) {
			t.Errorf("Service2 missing expected IP:port: 192.168.1.3:80 in VPC 1. Actual: %v", service2IPs.ToSlice())
		}
		assert.Equal(t, 1, service2IPs.Cardinality())
	})

	t.Run("EmptyPortRule", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:     model.Base{ID: 3},
				Name:     "service3",
				Type:     CUSTOM_SERVICE_TYPE_PORT,
				Resource: "192.168.1.1:80,192.168.1.2:443",
				VPCIDs:   1,
			},
			{
				Base:     model.Base{ID: 4},
				Name:     "service4",
				Type:     CUSTOM_SERVICE_TYPE_IP,
				Resource: "192.168.1.1,192.168.1.3", // 192.168.1.1 has empty port
				VPCIDs:   1,
			},
		}

		serviceRawData := newServiceRawData()
		result := serviceRawData.mergeCustomServices(md, services)

		// Service 3 should have one entry for 192.168.1.2
		service3IPs := result[3]
		if !service3IPs.Contains(customServiceIPPortKey{ip: "192.168.1.2", port: 443, vpcID: 1}) {
			t.Errorf("Service3 missing expected IP:port: 192.168.1.2:443 in VPC 1. Actual: %v", service3IPs.ToSlice())
		}
		if service3IPs.Cardinality() != 1 {
			t.Errorf("Service3 should have exactly 1 IP:port entry. Actual count: %d, Contents: %v",
				service3IPs.Cardinality(), service3IPs.ToSlice())
		}

		// Service 4 should have two entries for 192.168.1.1 and 192.168.1.3
		service4IPs := result[4]
		if !service4IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 0, vpcID: 1}) {
			t.Errorf("Service4 missing expected IP with empty port: 192.168.1.1 in VPC 1. Actual: %v", service4IPs.ToSlice())
		}
		if !service4IPs.Contains(customServiceIPPortKey{ip: "192.168.1.3", port: 0, vpcID: 1}) {
			t.Errorf("Service4 missing expected IP with empty port: 192.168.1.3 in VPC 1. Actual: %v", service4IPs.ToSlice())
		}
		if service4IPs.Cardinality() != 2 {
			t.Errorf("Service4 should have exactly 2 entries. Actual count: %d, Contents: %v",
				service4IPs.Cardinality(), service4IPs.ToSlice())
		}
	})

	t.Run("DifferentVPCs", func(t *testing.T) {
		services := []*model.CustomService{
			{
				Base:     model.Base{ID: 5},
				Name:     "service5",
				Type:     CUSTOM_SERVICE_TYPE_PORT,
				Resource: "192.168.1.1:80",
				VPCIDs:   1,
			},
			{
				Base:     model.Base{ID: 6},
				Name:     "service6",
				Type:     CUSTOM_SERVICE_TYPE_PORT,
				Resource: "192.168.1.1:80", // Same IP:port but different VPC
				VPCIDs:   2,
			},
		}

		serviceRawData := newServiceRawData()
		result := serviceRawData.mergeCustomServices(md, services)

		// Both services should have their entries (different VPCs)
		service5IPs := result[5]
		if !service5IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 1}) {
			t.Errorf("Service5 missing expected IP:port: 192.168.1.1:80 in VPC 1. Actual: %v", service5IPs.ToSlice())
		}
		if service5IPs.Cardinality() != 1 {
			t.Errorf("Service5 should have exactly 1 entry. Actual count: %d, Contents: %v",
				service5IPs.Cardinality(), service5IPs.ToSlice())
		}

		service6IPs := result[6]
		if !service6IPs.Contains(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 2}) {
			t.Errorf("Service6 missing expected IP:port: 192.168.1.1:80 in VPC 2. Actual: %v", service6IPs.ToSlice())
		}
		if service6IPs.Cardinality() != 1 {
			t.Errorf("Service6 should have exactly 1 entry. Actual count: %d, Contents: %v",
				service6IPs.Cardinality(), service6IPs.ToSlice())
		}
	})

	t.Run("EmptyServices", func(t *testing.T) {
		services := []*model.CustomService{}
		serviceRawData := newServiceRawData()
		result := serviceRawData.mergeCustomServices(md, services)
		assert.Equal(t, 0, len(result))
	})
}

// TestServiceDataOP_MergeCustomServices tests the ServiceDataOP.mergeCustomServices method
func TestServiceDataOP_MergeCustomServices(t *testing.T) {
	// Create mock custom services
	customServices := []*model.CustomService{
		{
			Base:     model.Base{ID: 1},
			Name:     "service1",
			VPCIDs:   1,
			Type:     CUSTOM_SERVICE_TYPE_PORT,
			Resource: "192.168.1.1:80",
		},
		{
			Base:     model.Base{ID: 2},
			Name:     "service2",
			VPCIDs:   2,
			Type:     CUSTOM_SERVICE_TYPE_IP,
			Resource: "192.168.1.2",
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
		if len(result) != 2 {
			t.Errorf("Expected 2 services, got %d", len(result))
		}

		// Verify service1 (with port)
		var service1Found bool
		var service2Found bool
		for _, svc := range result {
			if *svc.Id == 1 && len(svc.Ips) == 1 && svc.Ips[0] == "192.168.1.1" && len(svc.ServerPorts) == 1 && svc.ServerPorts[0] == 80 {
				service1Found = true
			}
			if *svc.Id == 2 && len(svc.Ips) == 1 && svc.Ips[0] == "192.168.1.2" && len(svc.ServerPorts) == 0 {
				service2Found = true
			}
		}
		if !service1Found {
			t.Errorf("Service 1 not found or incorrect")
		}
		if !service2Found {
			t.Errorf("Service 2 not found or incorrect")
		}
	})

	// Test multiple IP-port combinations for one service
	t.Run("MultipleIPPortCombinations", func(t *testing.T) {
		// Update custom services
		dbCache.SetCustomServices([]*model.CustomService{
			{
				Base:     model.Base{ID: 3},
				Name:     "service3",
				VPCIDs:   1,
				Type:     CUSTOM_SERVICE_TYPE_PORT,
				Resource: "192.168.1.10:80,192.168.1.10:443",
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
		if len(result) != 2 {
			t.Errorf("Expected 2 service infos, got %d", len(result))
		}

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
		if !port80Found {
			t.Errorf("Service with port 80 not found")
		}
		if !port443Found {
			t.Errorf("Service with port 443 not found")
		}
	})

	// Test empty mapping
	t.Run("EmptyMapping", func(t *testing.T) {
		// Update custom services
		dbCache.SetCustomServices([]*model.CustomService{
			{Base: model.Base{ID: 4}, Name: "service4", VPCIDs: 1},
		})

		// Set empty mapping
		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{}

		// Execute test
		result := s.mergeCustomServices(dbCache)

		// Verify results
		if len(result) != 0 {
			t.Errorf("Expected 0 services, got %d", len(result))
		}
	})

	// Test ID mismatch
	t.Run("IDMismatch", func(t *testing.T) {
		// Update custom services with ID=5
		dbCache.SetCustomServices([]*model.CustomService{
			{Base: model.Base{ID: 5}, Name: "service5", VPCIDs: 1},
		})

		// Set mapping with ID=6, not 5
		s.serviceRawData.customServiceIDToIPPorts = map[int]mapset.Set[customServiceIPPortKey]{
			6: mapset.NewSet(customServiceIPPortKey{ip: "192.168.1.1", port: 80, vpcID: 1}),
		}

		// Execute test
		result := s.mergeCustomServices(dbCache)

		// Verify results - should be empty due to ID mismatch
		if len(result) != 0 {
			t.Errorf("Expected 0 services due to ID mismatch, got %d", len(result))
		}
	})
}
