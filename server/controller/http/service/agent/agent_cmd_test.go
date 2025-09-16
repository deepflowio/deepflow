package agent

import (
	"fmt"
	"sync"
	"testing"
	"time"

	grpcapi "github.com/deepflowio/deepflow/message/agent"
)

// Tests for CMDRespManager
func TestCMDRespManager_Concurrent(t *testing.T) {
	resp := &CMDRespManager{
		requestID:                  1,
		ResponseDoneChan:           make(chan struct{}, 1),
		GetRemoteCommandsDoneChan:  make(chan struct{}, 1),
		GetLinuxNamespacesDoneChan: make(chan struct{}, 1),
	}

	var wg sync.WaitGroup
	concurrency := 20

	// Test concurrent AppendContent
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp.AppendContent([]byte("data"))
		}(i)
	}

	// Test concurrent SetErrorMessage
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp.SetErrorMessage("err")
		}(i)
	}

	// Test concurrent SetRemoteCommands
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp.SetRemoteCommands(nil)
		}(i)
	}

	// Test concurrent SetLinuxNamespaces
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp.SetLinuxNamespaces(nil)
		}(i)
	}

	// Test concurrent getContent, getErrorMessage, getRemoteCommands, getLinuxNamespaces
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = resp.getContent()
			_ = resp.getErrorMessage()
			_ = resp.getRemoteCommands()
			_ = resp.getLinuxNamespaces()
		}()
	}

	// Wait for all operations to complete before closing
	wg.Wait()

	// Now test the close operation (only once is needed since closeOnce prevents multiple closes)
	resp.close()
}

func TestCMDRespManager_BlockingChannel(t *testing.T) {
	resp := &CMDRespManager{
		requestID:                  3,
		ResponseDoneChan:           make(chan struct{}), // unbuffered to simulate blocking
		GetRemoteCommandsDoneChan:  make(chan struct{}),
		GetLinuxNamespacesDoneChan: make(chan struct{}),
	}

	done := make(chan struct{})

	go func() {
		// This will block until the channel is closed or a value is sent
		select {
		case <-resp.ResponseDoneChan:
		case <-time.After(2 * time.Second):
			t.Error("Timeout waiting for ResponseDoneChan to unblock")
		}
		close(done)
	}()

	// Give goroutine time to block
	time.Sleep(100 * time.Millisecond)

	// Closing should unblock
	resp.close()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Error("Goroutine did not unblock after close")
	}
}

func TestCMDRespManager_ConcurrentChannels(t *testing.T) {
	resp := &CMDRespManager{
		requestID:                  2,
		ResponseDoneChan:           make(chan struct{}, 1),
		GetRemoteCommandsDoneChan:  make(chan struct{}, 1),
		GetLinuxNamespacesDoneChan: make(chan struct{}, 1),
	}

	var wg sync.WaitGroup
	concurrency := 10

	// Test concurrent sends on all channels
	for i := 0; i < concurrency; i++ {
		wg.Add(3) // one for each channel
		go func() {
			defer wg.Done()
			select {
			case resp.ResponseDoneChan <- struct{}{}:
			default:
			}
		}()
		go func() {
			defer wg.Done()
			select {
			case resp.GetRemoteCommandsDoneChan <- struct{}{}:
			default:
			}
		}()
		go func() {
			defer wg.Done()
			select {
			case resp.GetLinuxNamespacesDoneChan <- struct{}{}:
			default:
			}
		}()
	}

	// Wait for all sends to complete
	wg.Wait()

	// Now test the close operation (only once is needed)
	resp.close()
}

// Tests for CMDManager
func TestCMDManager_Concurrent(t *testing.T) {
	manager := &CMDManager{
		key:         "test-key",
		RequestChan: make(chan *grpcapi.RemoteExecRequest, 1),
	}
	manager.latestRequestID.Store(0)

	var wg sync.WaitGroup
	concurrency := 20

	// Test concurrent newRespManager
	respManagers := make([]*CMDRespManager, concurrency)
	var requestIDs []uint64
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, resp := manager.newRespManager()
			respManagers[i] = resp
			requestIDs = append(requestIDs, id)
		}(i)
	}
	wg.Wait()

	// Verify requestIDs are unique
	seen := make(map[uint64]bool)
	for _, id := range requestIDs {
		if seen[id] {
			t.Errorf("Duplicate request ID found: %d", id)
		}
		seen[id] = true
	}

	// Test concurrent GetRespManager
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := manager.GetRespManager(uint64(i + 1))
			if resp == nil {
				t.Error("GetRespManager returned nil")
			}
		}(i)
	}
	wg.Wait()

	// Test concurrent removeRespManager
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			manager.removeRespManager(uint64(i + 1))
		}(i)
	}
	wg.Wait()

	// Verify all respManagers were removed
	for _, id := range requestIDs {
		if _, exists := manager.requestIDToResp.Load(id); exists {
			t.Errorf("Response manager with ID %d still exists after removal", id)
		}
	}
}

func TestCMDManager_BlockingChannel(t *testing.T) {
	manager := &CMDManager{
		key:         "test-key",
		RequestChan: make(chan *grpcapi.RemoteExecRequest), // unbuffered channel
	}

	// Test blocking send on RequestChan
	done := make(chan struct{})
	go func() {
		req := &grpcapi.RemoteExecRequest{}
		select {
		case manager.RequestChan <- req:
		case <-time.After(100 * time.Millisecond):
			// Expected to timeout as no one is receiving
		}
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(200 * time.Millisecond):
		t.Error("Goroutine blocked longer than expected")
	}
}

func TestCMDManager_ConcurrentMapOperations(t *testing.T) {
	manager := &CMDManager{
		key:         "test-key",
		RequestChan: make(chan *grpcapi.RemoteExecRequest, 1),
	}

	var wg sync.WaitGroup
	concurrency := 20

	// Test concurrent Store and Load operations on requestIDToResp
	for i := 0; i < concurrency; i++ {
		wg.Add(2) // one for store, one for load
		id := uint64(i)
		resp := &CMDRespManager{requestID: id}

		go func() {
			defer wg.Done()
			manager.requestIDToResp.Store(id, resp)
		}()

		go func() {
			defer wg.Done()
			_, _ = manager.requestIDToResp.Load(id)
		}()
	}
	wg.Wait()

	// Test concurrent Store/Load/Delete operations
	for i := 0; i < concurrency; i++ {
		wg.Add(3) // store, load, delete
		id := uint64(i)
		resp := &CMDRespManager{requestID: id}

		go func() {
			defer wg.Done()
			manager.requestIDToResp.Store(id, resp)
		}()

		go func() {
			defer wg.Done()
			_, _ = manager.requestIDToResp.Load(id)
		}()

		go func() {
			defer wg.Done()
			manager.requestIDToResp.Delete(id)
		}()
	}
	wg.Wait()
}

func TestCMDManager_AtomicOperations(t *testing.T) {
	manager := &CMDManager{
		key:         "test-key",
		RequestChan: make(chan *grpcapi.RemoteExecRequest, 1),
	}
	manager.latestRequestID.Store(0)

	var wg sync.WaitGroup
	concurrency := 1000

	// Test concurrent atomic operations on latestRequestID
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			manager.latestRequestID.Add(1)
		}()
	}
	wg.Wait()

	// Verify the final value
	finalValue := manager.latestRequestID.Load()
	if finalValue != uint64(concurrency) {
		t.Errorf("Expected latestRequestID to be %d, got %d", concurrency, finalValue)
	}
}

func TestCMDManager_CloseOperations(t *testing.T) {
	manager := &CMDManager{
		key:         "test-key",
		RequestChan: make(chan *grpcapi.RemoteExecRequest, 1),
	}

	// Create some response managers
	for i := 0; i < 5; i++ {
		id, resp := manager.newRespManager()
		if resp == nil {
			t.Errorf("Failed to create response manager %d", i)
		}
		if id == 0 {
			t.Errorf("Invalid request ID %d", i)
		}
	}

	// Test close
	manager.close()

	// Verify RequestChan is closed
	select {
	case _, ok := <-manager.RequestChan:
		if ok {
			t.Error("RequestChan should be closed")
		}
	default:
		// Channel might not be drained yet, which is fine
	}

	// Verify we can't send to RequestChan anymore
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when sending to closed channel")
		}
	}()
	manager.RequestChan <- &grpcapi.RemoteExecRequest{}
}

func TestCMDManager_Integration(t *testing.T) {
	key := "test-integration-key"
	startID := uint64(100)

	// Test NewAgentCMDManagerIfNotExist
	manager := NewAgentCMDManagerIfNotExist(key, startID)
	if manager == nil {
		t.Fatal("Failed to create new manager")
	}

	// Verify initial state
	if !manager.IsValid() {
		t.Error("New manager should be valid")
	}
	if manager.key != key {
		t.Errorf("Expected key %s, got %s", key, manager.key)
	}
	if manager.latestRequestID.Load() != startID {
		t.Errorf("Expected requestID %d, got %d", startID, manager.latestRequestID.Load())
	}

	// Test creating same manager again
	manager2 := NewAgentCMDManagerIfNotExist(key, startID+1)
	if manager2 != manager {
		t.Error("Should return existing manager for same key")
	}

	// Test concurrent operations in realistic scenario
	var wg sync.WaitGroup
	concurrency := 10

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// Create new response manager
			id, resp := manager.newRespManager()
			if !resp.IsValid() {
				t.Errorf("Response manager %d is invalid", i)
			}

			// Use it
			resp.SetErrorMessage(fmt.Sprintf("test-%d", i))

			// Get it again
			resp2 := manager.GetRespManager(id)
			if resp2 != resp {
				t.Errorf("Got different response manager for ID %d", id)
			}

			// Remove it
			manager.removeRespManager(id)
		}(i)
	}
	wg.Wait()

	// Test cleanup
	RemoveAgentCMDManager(key)

	// Verify manager was removed
	if m := GetAgentCMDManager(key); m.IsValid() {
		t.Error("Manager should have been removed")
	}
}
