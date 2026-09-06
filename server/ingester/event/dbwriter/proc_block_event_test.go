package dbwriter

import (
	"testing"

	"github.com/deepflowio/deepflow/server/ingester/event/common"
)

func TestAcquireProcBlockEventStoreDefaults(t *testing.T) {
	store := AcquireProcBlockEventStore()
	defer store.Release()

	if !store.IsIPv4 {
		t.Fatalf("AcquireProcBlockEventStore() IsIPv4 = false, want true")
	}
	if store.StoreEventType != common.PROC_BLOCK_EVENT {
		t.Fatalf("AcquireProcBlockEventStore() StoreEventType = %v, want %v", store.StoreEventType, common.PROC_BLOCK_EVENT)
	}
}
