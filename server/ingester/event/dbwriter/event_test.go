package dbwriter

import (
	"testing"

	eventcommon "github.com/deepflowio/deepflow/server/ingester/event/common"
	exporterconfig "github.com/deepflowio/deepflow/server/ingester/exporters/config"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
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

func TestGenEventCKTableDisables1SAggrForNewAiAgentTables(t *testing.T) {
	tests := []struct {
		table string
		want  bool
	}{
		{eventcommon.FILE_EVENT.TableName(), true},
		{eventcommon.FILE_AGG_EVENT.TableName(), false},
		{eventcommon.FILE_MGMT_EVENT.TableName(), false},
		{eventcommon.PROC_PERM_EVENT.TableName(), false},
		{eventcommon.PROC_OPS_EVENT.TableName(), false},
	}

	for _, tt := range tests {
		t.Run(tt.table, func(t *testing.T) {
			table := GenEventCKTable("test_cluster", "policy", tt.table, "clickhouse", 24, &ckdb.ColdStorage{})
			if table.Aggr1S != tt.want {
				t.Fatalf("table %s Aggr1S = %v, want %v", tt.table, table.Aggr1S, tt.want)
			}
		})
	}
}
