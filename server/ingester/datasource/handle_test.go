package datasource

import "testing"

func TestNewAiAgentEventDatasourcesRegistered(t *testing.T) {
	tests := []struct {
		name       string
		datasource DatasourceModifiedOnly
		wantDB     string
		wantTable  string
	}{
		{
			name:       "file agg event",
			datasource: EVENT_FILE_AGG_EVENT,
			wantDB:     "event",
			wantTable:  "file_agg_event",
		},
		{
			name:       "file mgmt event",
			datasource: EVENT_FILE_MGMT_EVENT,
			wantDB:     "event",
			wantTable:  "file_mgmt_event",
		},
		{
			name:       "proc perm event",
			datasource: EVENT_PROC_PERM_EVENT,
			wantDB:     "event",
			wantTable:  "proc_perm_event",
		},
		{
			name:       "proc ops event",
			datasource: EVENT_PROC_OPS_EVENT,
			wantDB:     "event",
			wantTable:  "proc_ops_event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ok := DatasourceModifiedOnlyIDMap[tt.datasource]
			if !ok {
				t.Fatalf("datasource %q not registered", tt.datasource)
			}
			if info.DB != tt.wantDB {
				t.Fatalf("datasource %q db = %q, want %q", tt.datasource, info.DB, tt.wantDB)
			}
			if len(info.Tables) != 1 || info.Tables[0] != tt.wantTable {
				t.Fatalf("datasource %q tables = %v, want [%q]", tt.datasource, info.Tables, tt.wantTable)
			}
		})
	}
}
