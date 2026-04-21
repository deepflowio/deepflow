/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package service

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func Test_getTableName(t *testing.T) {
	type args struct {
		collection string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "network",
			args: args{
				collection: "flow_metrics.network*",
			},
			want: "network",
		},
		{
			name: "application",
			args: args{
				collection: "flow_metrics.application*",
			},
			want: "application",
		},
		{
			name: "flow_log.l4_flow_log",
			args: args{
				collection: "flow_log.l4_flow_log",
			},
			want: "flow_log.l4_flow_log",
		},
		{
			name: "deepflow_system",
			args: args{
				collection: "deepflow_system.*",
			},
			want: "deepflow_system",
		},
		{
			name: "event.file_agg_event",
			args: args{
				collection: "event.file_agg_event",
			},
			want: "event.file_agg_event",
		},
		{
			name: "event.file_mgmt_event",
			args: args{
				collection: "event.file_mgmt_event",
			},
			want: "event.file_mgmt_event",
		},
		{
			name: "event.proc_perm_event",
			args: args{
				collection: "event.proc_perm_event",
			},
			want: "event.proc_perm_event",
		},
		{
			name: "event.proc_ops_event",
			args: args{
				collection: "event.proc_ops_event",
			},
			want: "event.proc_ops_event",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getTableName(tt.args.collection); got != tt.want {
				t.Errorf("getTableName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getName(t *testing.T) {
	type args struct {
		interval   int
		collection string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "1s",
			args: args{
				interval:   1,
				collection: "flow_metrics.network*",
			},
			want:    "1s",
			wantErr: false,
		},
		{
			name: "1m",
			args: args{
				interval:   60 * 1,
				collection: "flow_metrics.application*",
			},
			want:    "1m",
			wantErr: false,
		},
		{
			name: "1h",
			args: args{
				interval:   60 * 60 * 1,
				collection: "flow_metrics.application*",
			},
			want:    "1h",
			wantErr: false,
		},
		{
			name: "1d",
			args: args{
				interval:   60 * 60 * 24 * 1,
				collection: "flow_metrics.application*",
			},
			want:    "1d",
			wantErr: false,
		},
		{
			name: "flow_log.l4_flow_log",
			args: args{
				interval:   0,
				collection: "flow_log.l4_flow_log",
			},
			want:    "flow_log.l4_flow_log",
			wantErr: false,
		},
		{
			name: "deepflow_system",
			args: args{
				interval:   0,
				collection: "deepflow_system.*",
			},
			want:    "deepflow_system",
			wantErr: false,
		},
		{
			name: "prometheus",
			args: args{
				interval:   0,
				collection: "prometheus.*",
			},
			want:    "prometheus",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getName(tt.args.interval, tt.args.collection)
			if (err != nil) != tt.wantErr {
				t.Errorf("getName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLinkedRetentionCollections(t *testing.T) {
	tests := []struct {
		name       string
		collection string
		want       []string
	}{
		{
			name:       "file agg event",
			collection: "event.file_agg_event",
			want: []string{
				"event.file_agg_event",
				"event.file_mgmt_event",
				"event.proc_perm_event",
				"event.proc_ops_event",
			},
		},
		{
			name:       "file mgmt event",
			collection: "event.file_mgmt_event",
			want: []string{
				"event.file_agg_event",
				"event.file_mgmt_event",
				"event.proc_perm_event",
				"event.proc_ops_event",
			},
		},
		{
			name:       "proc perm event",
			collection: "event.proc_perm_event",
			want: []string{
				"event.file_agg_event",
				"event.file_mgmt_event",
				"event.proc_perm_event",
				"event.proc_ops_event",
			},
		},
		{
			name:       "proc ops event",
			collection: "event.proc_ops_event",
			want: []string{
				"event.file_agg_event",
				"event.file_mgmt_event",
				"event.proc_perm_event",
				"event.proc_ops_event",
			},
		},
		{
			name:       "non ai event collection",
			collection: "event.event",
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := linkedRetentionCollections(tt.collection)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("linkedRetentionCollections(%q) = %v, want %v", tt.collection, got, tt.want)
			}
		})
	}
}

func TestResolveRetentionTargets(t *testing.T) {
	all := []metadbmodel.DataSource{
		{Lcuuid: "a", DataTableCollection: "event.file_agg_event", RetentionTime: 24},
		{Lcuuid: "b", DataTableCollection: "event.file_mgmt_event", RetentionTime: 24},
		{Lcuuid: "c", DataTableCollection: "event.proc_perm_event", RetentionTime: 24},
		{Lcuuid: "d", DataTableCollection: "event.proc_ops_event", RetentionTime: 24},
		{Lcuuid: "e", DataTableCollection: "event.event", RetentionTime: 24},
	}

	t.Run("ai agent event resolves to linked group", func(t *testing.T) {
		got := resolveRetentionTargets(all[0], all)
		want := []metadbmodel.DataSource{
			all[0], all[1], all[2], all[3],
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("resolveRetentionTargets(ai-agent) = %v, want %v", got, want)
		}
	})

	t.Run("non linked collection resolves to self only", func(t *testing.T) {
		got := resolveRetentionTargets(all[4], all)
		want := []metadbmodel.DataSource{all[4]}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("resolveRetentionTargets(non-linked) = %v, want %v", got, want)
		}
	})
}

func TestUpdateDataSourceLinksAIAgentRetentionGroup(t *testing.T) {
	gormDB, err := gorm.Open(
		sqlite.Open("file::memory:?cache=shared"),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("get sql.DB failed: %v", err)
	}
	defer sqlDB.Close()

	if err := gormDB.AutoMigrate(&metadbmodel.DataSource{}, &metadbmodel.Analyzer{}); err != nil {
		t.Fatalf("auto migrate failed: %v", err)
	}

	retention := 7 * 24
	dataSources := []metadbmodel.DataSource{
		{ID: 27, DisplayName: "事件-文件读写聚合事件", DataTableCollection: "event.file_agg_event", RetentionTime: retention, Lcuuid: "a", UpdatedAt: time.Now()},
		{ID: 28, DisplayName: "事件-文件管理事件", DataTableCollection: "event.file_mgmt_event", RetentionTime: retention, Lcuuid: "b", UpdatedAt: time.Now()},
		{ID: 29, DisplayName: "事件-进程权限事件", DataTableCollection: "event.proc_perm_event", RetentionTime: retention, Lcuuid: "c", UpdatedAt: time.Now()},
		{ID: 30, DisplayName: "事件-进程操作事件", DataTableCollection: "event.proc_ops_event", RetentionTime: retention, Lcuuid: "d", UpdatedAt: time.Now()},
		{ID: 31, DisplayName: "事件-资源变更事件", DataTableCollection: "event.event", RetentionTime: retention, Lcuuid: "e", UpdatedAt: time.Now()},
	}
	if err := gormDB.Create(&dataSources).Error; err != nil {
		t.Fatalf("insert data sources failed: %v", err)
	}
	analyzers := []metadbmodel.Analyzer{
		{ID: 1, Name: "analyzer-1", IP: "10.0.0.1", Lcuuid: "analyzer-1"},
	}
	if err := gormDB.Create(&analyzers).Error; err != nil {
		t.Fatalf("insert analyzers failed: %v", err)
	}

	db := &metadb.DB{
		DB:             gormDB,
		ORGID:          1,
		Name:           "test",
		LogPrefixORGID: logger.NewORGPrefix(1),
		LogPrefixName:  metadb.NewDBNameLogPrefix("test"),
	}

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	patches.ApplyFunc(metadb.GetDB, func(orgID int) (*metadb.DB, error) {
		return db, nil
	})

	modifiedCollections := make([]string, 0, 4)
	patches.ApplyMethod(reflect.TypeOf(&DataSource{}), "CallIngesterAPIModRP",
		func(_ *DataSource, orgID int, ip string, dataSource metadbmodel.DataSource) error {
			modifiedCollections = append(modifiedCollections, dataSource.DataTableCollection)
			return nil
		})

	newRetention := 30 * 24
	svc := &DataSource{
		cfg: &config.ControllerConfig{
			Spec: config.Specification{
				DataSourceRetentionTimeMax: 24000,
			},
		},
		resourceAccess: &ResourceAccess{
			UserInfo: &httpcommon.UserInfo{Type: common.USER_TYPE_SUPER_ADMIN, ORGID: 1},
		},
	}

	resp, err := svc.UpdateDataSource(1, "a", model.DataSourceUpdate{RetentionTime: &newRetention})
	if err != nil {
		t.Fatalf("UpdateDataSource() error = %v", err)
	}
	if resp.RetentionTime != newRetention {
		t.Fatalf("returned retention = %d, want %d", resp.RetentionTime, newRetention)
	}

	var updated []metadbmodel.DataSource
	if err := gormDB.Order("id asc").Find(&updated).Error; err != nil {
		t.Fatalf("query updated data sources failed: %v", err)
	}

	for _, item := range updated[:4] {
		if item.RetentionTime != newRetention {
			t.Fatalf("collection %s retention = %d, want %d", item.DataTableCollection, item.RetentionTime, newRetention)
		}
	}
	if updated[4].RetentionTime != retention {
		t.Fatalf("non-linked collection retention = %d, want %d", updated[4].RetentionTime, retention)
	}

	wantCollections := []string{
		"event.file_agg_event",
		"event.file_mgmt_event",
		"event.proc_perm_event",
		"event.proc_ops_event",
	}
	if !reflect.DeepEqual(modifiedCollections, wantCollections) {
		t.Fatalf("CallIngesterAPIModRP collections = %v, want %v", modifiedCollections, wantCollections)
	}
}

func TestUpdateDataSourceMarksWholeAIAgentRetentionGroupExceptionOnFailure(t *testing.T) {
	gormDB, err := gorm.Open(
		sqlite.Open("file::memory:?cache=shared"),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("get sql.DB failed: %v", err)
	}
	defer sqlDB.Close()

	if err := gormDB.AutoMigrate(&metadbmodel.DataSource{}, &metadbmodel.Analyzer{}); err != nil {
		t.Fatalf("auto migrate failed: %v", err)
	}

	retention := 7 * 24
	dataSources := []metadbmodel.DataSource{
		{ID: 27, DisplayName: "事件-文件读写聚合事件", DataTableCollection: "event.file_agg_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "a", UpdatedAt: time.Now()},
		{ID: 28, DisplayName: "事件-文件管理事件", DataTableCollection: "event.file_mgmt_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "b", UpdatedAt: time.Now()},
		{ID: 29, DisplayName: "事件-进程权限事件", DataTableCollection: "event.proc_perm_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "c", UpdatedAt: time.Now()},
		{ID: 30, DisplayName: "事件-进程操作事件", DataTableCollection: "event.proc_ops_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "d", UpdatedAt: time.Now()},
		{ID: 31, DisplayName: "事件-资源变更事件", DataTableCollection: "event.event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "e", UpdatedAt: time.Now()},
	}
	if err := gormDB.Create(&dataSources).Error; err != nil {
		t.Fatalf("insert data sources failed: %v", err)
	}
	analyzers := []metadbmodel.Analyzer{
		{ID: 1, Name: "analyzer-1", IP: "10.0.0.1", Lcuuid: "analyzer-1"},
	}
	if err := gormDB.Create(&analyzers).Error; err != nil {
		t.Fatalf("insert analyzers failed: %v", err)
	}

	db := &metadb.DB{
		DB:             gormDB,
		ORGID:          1,
		Name:           "test",
		LogPrefixORGID: logger.NewORGPrefix(1),
		LogPrefixName:  metadb.NewDBNameLogPrefix("test"),
	}

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	patches.ApplyFunc(metadb.GetDB, func(orgID int) (*metadb.DB, error) {
		return db, nil
	})

	patches.ApplyMethod(reflect.TypeOf(&DataSource{}), "CallIngesterAPIModRP",
		func(_ *DataSource, orgID int, ip string, dataSource metadbmodel.DataSource) error {
			if dataSource.DataTableCollection == "event.file_mgmt_event" {
				return fmt.Errorf("%w, forced failure", httpcommon.ErrorFail)
			}
			return nil
		})

	newRetention := 30 * 24
	svc := &DataSource{
		cfg: &config.ControllerConfig{
			Spec: config.Specification{
				DataSourceRetentionTimeMax: 24000,
			},
		},
		resourceAccess: &ResourceAccess{
			UserInfo: &httpcommon.UserInfo{Type: common.USER_TYPE_SUPER_ADMIN, ORGID: 1},
		},
	}

	if _, err := svc.UpdateDataSource(1, "a", model.DataSourceUpdate{RetentionTime: &newRetention}); err == nil {
		t.Fatal("UpdateDataSource() error = nil, want failure")
	}

	var updated []metadbmodel.DataSource
	if err := gormDB.Order("id asc").Find(&updated).Error; err != nil {
		t.Fatalf("query updated data sources failed: %v", err)
	}

	for _, item := range updated[:4] {
		if item.State != common.DATA_SOURCE_STATE_EXCEPTION {
			t.Fatalf("collection %s state = %d, want %d", item.DataTableCollection, item.State, common.DATA_SOURCE_STATE_EXCEPTION)
		}
		if item.RetentionTime != retention {
			t.Fatalf("collection %s retention = %d, want unchanged %d", item.DataTableCollection, item.RetentionTime, retention)
		}
	}

	if updated[4].State != common.DATA_SOURCE_STATE_NORMAL {
		t.Fatalf("non-linked collection state = %d, want %d", updated[4].State, common.DATA_SOURCE_STATE_NORMAL)
	}
}

func TestUpdateDataSourceRollsBackLinkedRetentionGroupOnMetadbFailure(t *testing.T) {
	gormDB, err := gorm.Open(
		sqlite.Open("file::memory:?cache=shared"),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("get sql.DB failed: %v", err)
	}
	defer sqlDB.Close()

	if err := gormDB.AutoMigrate(&metadbmodel.DataSource{}, &metadbmodel.Analyzer{}); err != nil {
		t.Fatalf("auto migrate failed: %v", err)
	}

	retention := 7 * 24
	dataSources := []metadbmodel.DataSource{
		{ID: 27, DisplayName: "事件-文件读写聚合事件", DataTableCollection: "event.file_agg_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "a", UpdatedAt: time.Now()},
		{ID: 28, DisplayName: "事件-文件管理事件", DataTableCollection: "event.file_mgmt_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "b", UpdatedAt: time.Now()},
		{ID: 29, DisplayName: "事件-进程权限事件", DataTableCollection: "event.proc_perm_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "c", UpdatedAt: time.Now()},
		{ID: 30, DisplayName: "事件-进程操作事件", DataTableCollection: "event.proc_ops_event", RetentionTime: retention, State: common.DATA_SOURCE_STATE_NORMAL, Lcuuid: "d", UpdatedAt: time.Now()},
	}
	if err := gormDB.Create(&dataSources).Error; err != nil {
		t.Fatalf("insert data sources failed: %v", err)
	}
	analyzers := []metadbmodel.Analyzer{
		{ID: 1, Name: "analyzer-1", IP: "10.0.0.1", Lcuuid: "analyzer-1"},
	}
	if err := gormDB.Create(&analyzers).Error; err != nil {
		t.Fatalf("insert analyzers failed: %v", err)
	}

	if _, err := sqlDB.Exec(`
CREATE TRIGGER fail_proc_perm_retention_update
BEFORE UPDATE ON data_source
WHEN NEW.data_table_collection = 'event.proc_perm_event'
BEGIN
    SELECT RAISE(FAIL, 'forced metadb update failure');
END;
`); err != nil {
		t.Fatalf("create trigger failed: %v", err)
	}

	db := &metadb.DB{
		DB:             gormDB,
		ORGID:          1,
		Name:           "test",
		LogPrefixORGID: logger.NewORGPrefix(1),
		LogPrefixName:  metadb.NewDBNameLogPrefix("test"),
	}

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	patches.ApplyFunc(metadb.GetDB, func(orgID int) (*metadb.DB, error) {
		return db, nil
	})

	patches.ApplyMethod(reflect.TypeOf(&DataSource{}), "CallIngesterAPIModRP",
		func(_ *DataSource, orgID int, ip string, dataSource metadbmodel.DataSource) error {
			return nil
		})

	newRetention := 30 * 24
	svc := &DataSource{
		cfg: &config.ControllerConfig{
			Spec: config.Specification{
				DataSourceRetentionTimeMax: 24000,
			},
		},
		resourceAccess: &ResourceAccess{
			UserInfo: &httpcommon.UserInfo{Type: common.USER_TYPE_SUPER_ADMIN, ORGID: 1},
		},
	}

	if _, err := svc.UpdateDataSource(1, "a", model.DataSourceUpdate{RetentionTime: &newRetention}); err == nil {
		t.Fatal("UpdateDataSource() error = nil, want metadb failure")
	}

	var updated []metadbmodel.DataSource
	if err := gormDB.Order("id asc").Find(&updated).Error; err != nil {
		t.Fatalf("query updated data sources failed: %v", err)
	}

	for _, item := range updated {
		if item.RetentionTime != retention {
			t.Fatalf("collection %s retention = %d, want rolled back %d", item.DataTableCollection, item.RetentionTime, retention)
		}
	}
}
