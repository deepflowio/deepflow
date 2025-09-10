package agent

import (
	"fmt"
	"testing"
	"time"

	grpcapi "github.com/deepflowio/deepflow/message/agent"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

// Mock VTap data for testing
type mockVTap struct {
	metadbmodel.VTap
}

type mockDB struct {
	vtap *mockVTap
}

func (m *mockDB) Where(query interface{}, args ...interface{}) metadb.DB {
	return m
}

func (m *mockDB) Find(dest interface{}) error {
	if vtap, ok := dest.(**metadbmodel.VTap); ok {
		*vtap = &m.vtap.VTap
	}
	return nil
}

func (m *mockDB) Close() error {
	return nil
}

func TestGetCMDAndNamespace(t *testing.T) {
	tests := []struct {
		name           string
		timeout        int
		orgID          int
		agentID        int
		ctrlIP         string
		ctrlMac        string
		simulateResp   func(*CMDRespManager)
		expectedError  bool
		expectedErrStr string
	}{
		{
			name:    "successful case - commands and namespaces received",
			timeout: 1,
			orgID:   1,
			agentID: 1,
			ctrlIP:  "192.168.1.1",
			ctrlMac: "00:11:22:33:44:55",
			simulateResp: func(resp *CMDRespManager) {
				go func() {
					time.Sleep(100 * time.Millisecond)
					// Set commands
					cmd := &grpcapi.RemoteCommand{}
					resp.SetRemoteCommands([]*grpcapi.RemoteCommand{cmd})
					resp.GetRemoteCommandsDoneChan <- struct{}{}

					// Set namespaces
					time.Sleep(50 * time.Millisecond)
					var nsID uint64 = 1
					ns := &grpcapi.LinuxNamespace{Id: &nsID}
					resp.SetLinuxNamespaces([]*grpcapi.LinuxNamespace{ns})
					resp.GetLinuxNamespacesDoneChan <- struct{}{}
				}()
			},
			expectedError: false,
		},
		{
			name:    "timeout case",
			timeout: 1,
			orgID:   1,
			agentID: 2,
			ctrlIP:  "192.168.1.2",
			ctrlMac: "00:11:22:33:44:66",
			simulateResp: func(resp *CMDRespManager) {
				// Don't send any response to trigger timeout
			},
			expectedError:  true,
			expectedErrStr: "timeout",
		},
		{
			name:    "command manager lost case",
			timeout: 1,
			orgID:   1,
			agentID: 3,
			ctrlIP:  "192.168.1.3",
			ctrlMac: "00:11:22:33:44:77",
			simulateResp: func(resp *CMDRespManager) {
				go func() {
					time.Sleep(100 * time.Millisecond)
					resp.close() // Close channels to simulate lost connection
				}()
			},
			expectedError:  true,
			expectedErrStr: "command manager is lost",
		},
		{
			name:    "error response case",
			timeout: 1,
			orgID:   1,
			agentID: 4,
			ctrlIP:  "192.168.1.4",
			ctrlMac: "00:11:22:33:44:88",
			simulateResp: func(resp *CMDRespManager) {
				go func() {
					time.Sleep(100 * time.Millisecond)
					resp.SetErrorMessage("test error")
					resp.ResponseDoneChan <- struct{}{}
				}()
			},
			expectedError:  true,
			expectedErrStr: "test error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a manager for this test
			key := fmt.Sprintf("%s-%s", tc.ctrlIP, tc.ctrlMac)
			manager := NewAgentCMDManagerIfNotExist(key, 0)

			// Set up response handling
			if tc.simulateResp != nil {
				go func() {
					for req := range manager.RequestChan {
						if req == nil {
							continue
						}
						resp := manager.GetRespManager(*req.RequestId)
						if resp != nil {
							tc.simulateResp(resp)
						}
					}
				}()
			}

			// Store manager in global map
			keyToAgentCMDManager.Store(key, manager)

			// Call the function
			result, err := GetCMDAndNamespace(tc.timeout, tc.orgID, tc.agentID)

			// Clean up
			RemoveAgentCMDManager(key)

			// Verify results
			if tc.expectedError {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if tc.expectedErrStr != "" && !contains(err.Error(), tc.expectedErrStr) {
					t.Errorf("expected error containing '%s' but got '%s'", tc.expectedErrStr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("expected result but got nil")
				} else {
					if len(result.RemoteCommands) == 0 {
						t.Error("expected RemoteCommands but got none")
					}
					if len(result.LinuxNamespaces) == 0 {
						t.Error("expected LinuxNamespaces but got none")
					}
				}
			}
		})
	}
}

func TestGetCMDAndNamespace_Concurrent(t *testing.T) {
	numConcurrent := 10
	done := make(chan bool, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(i int) {
			key := fmt.Sprintf("192.168.1.%d-00:11:22:33:44:%02x", i, i)
			manager := NewAgentCMDManagerIfNotExist(key, 0)

			// Simulate response handling
			go func() {
				for req := range manager.RequestChan {
					if req == nil {
						continue
					}
					resp := manager.GetRespManager(*req.RequestId)
					if resp != nil {
						go func() {
							time.Sleep(50 * time.Millisecond)
							cmd := &grpcapi.RemoteCommand{}
							resp.SetRemoteCommands([]*grpcapi.RemoteCommand{cmd})
							resp.GetRemoteCommandsDoneChan <- struct{}{}

							time.Sleep(50 * time.Millisecond)
							var nsID uint64 = uint64(i)
							ns := &grpcapi.LinuxNamespace{Id: &nsID}
							resp.SetLinuxNamespaces([]*grpcapi.LinuxNamespace{ns})
							resp.GetLinuxNamespacesDoneChan <- struct{}{}
						}()
					}
				}
			}()

			// Store manager in global map
			keyToAgentCMDManager.Store(key, manager)

			// Call the function
			result, err := GetCMDAndNamespace(2, 1, i)
			if err != nil {
				t.Errorf("concurrent test %d failed: %v", i, err)
			}
			if result != nil && (len(result.RemoteCommands) == 0 || len(result.LinuxNamespaces) == 0) {
				t.Errorf("concurrent test %d: missing commands or namespaces", i)
			}

			RemoveAgentCMDManager(key)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numConcurrent; i++ {
		<-done
	}
}

func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && s[0:len(substr)] == substr
}
