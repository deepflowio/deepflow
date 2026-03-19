package dbwriter

import (
	"testing"

	eventcommon "github.com/deepflowio/deepflow/server/ingester/event/common"
	exporterconfig "github.com/deepflowio/deepflow/server/ingester/exporters/config"
)

func TestEventStoreDataSourceForNewAiAgentTables(t *testing.T) {
	tests := []struct {
		name  string
		store EventStore
		want  uint32
	}{
		{
			name:  "file event",
			store: EventStore{StoreEventType: eventcommon.FILE_EVENT, IsFileEvent: true},
			want:  uint32(exporterconfig.FILE_EVENT),
		},
		{
			name:  "file agg event",
			store: EventStore{StoreEventType: eventcommon.FILE_AGG_EVENT, IsFileEvent: true},
			want:  uint32(exporterconfig.FILE_AGG_EVENT),
		},
		{
			name:  "file mgmt event",
			store: EventStore{StoreEventType: eventcommon.FILE_MGMT_EVENT, IsFileEvent: true},
			want:  uint32(exporterconfig.FILE_MGMT_EVENT),
		},
		{
			name:  "proc perm event",
			store: EventStore{StoreEventType: eventcommon.PROC_PERM_EVENT},
			want:  uint32(exporterconfig.PROC_PERM_EVENT),
		},
		{
			name:  "proc ops event",
			store: EventStore{StoreEventType: eventcommon.PROC_OPS_EVENT},
			want:  uint32(exporterconfig.PROC_OPS_EVENT),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.store.DataSource(); got != tt.want {
				t.Fatalf("DataSource() = %d, want %d", got, tt.want)
			}
		})
	}
}
