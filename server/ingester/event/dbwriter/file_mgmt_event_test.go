package dbwriter

import "testing"

func TestAcquireFileMgmtEventStoreDefaultsToIPv4(t *testing.T) {
	store := AcquireFileMgmtEventStore()
	defer store.Release()

	if !store.IsIPv4 {
		t.Fatalf("AcquireFileMgmtEventStore() IsIPv4 = false, want true")
	}
}
