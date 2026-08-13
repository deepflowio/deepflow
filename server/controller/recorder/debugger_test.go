package recorder

import (
	"strings"
	"testing"
	"time"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
)

// TestGetResourceFieldCountsString tests the GetResourceFieldCountsString function with various scenarios
func TestGetResourceFieldCountsString(t *testing.T) {
	// Test case 1: Empty lists and maps (0 values)
	t.Run("EmptyValues", func(t *testing.T) {
		resource := model.Resource{
			SubDomains:         []model.SubDomain{},
			VMs:                []model.VM{},
			VPCs:               []model.VPC{},
			SubDomainResources: map[string]model.SubDomainResource{},
		}

		result := GetResourceFieldCountsString(resource)

		// Expected result should contain all fields with 0 counts
		expectedParts := []string{
			"SubDomains=0",
			"VMs=0",
			"VPCs=0",
			"SubDomainResources=0",
		}

		for _, part := range expectedParts {
			if !strings.Contains(result, part) {
				t.Errorf("Expected to find '%s' in result: %s", part, result)
			}
		}

		// Ensure no map entries are shown since all maps are empty
		if strings.Contains(result, "[") && strings.Contains(result, "]") {
			t.Errorf("No map entries should be present for empty maps, got: %s", result)
		}
	})

	// Test case 2: Non-empty lists and maps
	t.Run("WithValues", func(t *testing.T) {
		resource := model.Resource{
			SubDomains:         []model.SubDomain{{Lcuuid: "sd1", Name: "subdomain1"}},
			VMs:                []model.VM{{Name: "test-vm-1", Lcuuid: "vm1"}, {Name: "test-vm-2", Lcuuid: "vm2"}},
			VPCs:               []model.VPC{{Name: "test-vpc-1", Lcuuid: "vpc1"}},
			SubDomainResources: map[string]model.SubDomainResource{"sub1": {}},
		}

		result := GetResourceFieldCountsString(resource)

		// Check that we have the expected counts
		expectedContains := []string{
			"SubDomains=1",
			"VMs=2",
			"VPCs=1",
			"SubDomainResources=1",
		}

		for _, exp := range expectedContains {
			if !strings.Contains(result, exp) {
				t.Errorf("Expected to find '%s' in result: %s", exp, result)
			}
		}

		// Check that the map entry is properly formatted
		if !strings.Contains(result, "SubDomainResources[sub1]=") {
			t.Errorf("Expected map entry SubDomainResources[sub1]= to be present, got: %s", result)
		}
	})

	// Test case 3: Map with flat structure having 0 values and non-zero values
	t.Run("MapWithFlatStructure", func(t *testing.T) {
		// Test empty SubDomainResource (all slice fields are zero values)
		resourceEmpty := model.Resource{
			SubDomainResources: map[string]model.SubDomainResource{
				"empty": {}, // All slice fields in SubDomainResource are zero values (empty slices)
			},
		}

		resultEmpty := GetResourceFieldCountsString(resourceEmpty)

		// Should contain the map count
		if !strings.Contains(resultEmpty, "SubDomainResources=1") {
			t.Errorf("Expected SubDomainResources=1 in result: %s", resultEmpty)
		}

		// The 'empty' entry should show all slice counts as 0
		if !strings.Contains(resultEmpty, "SubDomainResources[empty]=") {
			t.Errorf("Expected SubDomainResources[empty]= entry in result: %s", resultEmpty)
		}

		// Even though SubDomainResource is empty, it should still show all slice fields as 0
		// Since SubDomainResource has many slice fields, the result should contain multiple "=0" entries
		zeroCountFound := strings.Contains(resultEmpty, "=0, ") || strings.HasSuffix(resultEmpty, "=0")
		if !zeroCountFound {
			t.Errorf("Expected to find zero counts in SubDomainResources[empty] entry, got: %s", resultEmpty)
		}

		// Test SubDomainResource with non-zero values
		resourceWithData := model.Resource{
			SubDomainResources: map[string]model.SubDomainResource{
				"with-data": { // SubDomainResource with some data in slices
					Networks: []model.Network{{Lcuuid: "net1", Name: "network1"}, {Lcuuid: "net2", Name: "network2"}},
					Subnets:  []model.Subnet{{Lcuuid: "subnet1", Name: "subnet1"}},
					Pods:     []model.Pod{{Lcuuid: "pod1", Name: "pod1"}, {Lcuuid: "pod2", Name: "pod2"}, {Lcuuid: "pod3", Name: "pod3"}},
				},
			},
		}

		resultWithData := GetResourceFieldCountsString(resourceWithData)

		// Should contain the map count
		if !strings.Contains(resultWithData, "SubDomainResources=1") {
			t.Errorf("Expected SubDomainResources=1 in result: %s", resultWithData)
		}

		// The 'with-data' entry should show the count of slices inside the SubDomainResource
		if !strings.Contains(resultWithData, "SubDomainResources[with-data]=") {
			t.Errorf("Expected SubDomainResources[with-data]= entry in result: %s", resultWithData)
		}

		// Verify specific counts for the slices
		if !strings.Contains(resultWithData, "Networks=2") {
			t.Errorf("Expected Networks=2 in the with-data entry, got: %s", resultWithData)
		}
		if !strings.Contains(resultWithData, "Subnets=1") {
			t.Errorf("Expected Subnets=1 in the with-data entry, got: %s", resultWithData)
		}
		if !strings.Contains(resultWithData, "Pods=3") {
			t.Errorf("Expected Pods=3 in the with-data entry, got: %s", resultWithData)
		}
	})

	// Test case 4: Resource with only basic fields (no slices or maps)
	t.Run("BasicFieldsOnly", func(t *testing.T) {
		// Create a resource with basic fields that don't contribute to the count
		resource := model.Resource{
			Verified:           true,
			ErrorState:         0,
			ErrorMessage:       "",
			SyncAt:             time.Now(),
			SubDomains:         []model.SubDomain{},                  // Empty slice
			SubDomainResources: map[string]model.SubDomainResource{}, // Empty map
		}

		result := GetResourceFieldCountsString(resource)

		// Should only show slice and map fields, not basic fields like Verified, ErrorState, etc.
		if !strings.Contains(result, "SubDomains=0") {
			t.Errorf("Expected SubDomains=0 in result: %s", result)
		}
		if !strings.Contains(result, "SubDomainResources=0") {
			t.Errorf("Expected SubDomainResources=0 in result: %s", result)
		}

		// Basic fields shouldn't appear in the result
		if strings.Contains(result, "Verified=") {
			t.Errorf("Basic fields like Verified should not appear in result: %s", result)
		}
	})
}
