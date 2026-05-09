package common

import "testing"

func TestNewAiAgentEventTypesTableName(t *testing.T) {
	tests := []struct {
		eventType EventType
		want      string
	}{
		{FILE_AGG_EVENT, "file_agg_event"},
		{FILE_MGMT_EVENT, "file_mgmt_event"},
		{PROC_PERM_EVENT, "proc_perm_event"},
		{PROC_OPS_EVENT, "proc_ops_event"},
	}

	for _, tt := range tests {
		if got := tt.eventType.TableName(); got != tt.want {
			t.Fatalf("event type %v table name = %q, want %q", tt.eventType, got, tt.want)
		}
	}
}
