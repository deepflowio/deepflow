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

package vtap

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/common"
	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlconfig "github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/monitor/config"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

const (
	TEST_DB_FILE = "./vtap_test.db"
)

type VTapTestSuite struct {
	suite.Suite
	db *gorm.DB
}

func TestVTapSuite(t *testing.T) {
	if _, err := os.Stat(TEST_DB_FILE); err == nil {
		os.Remove(TEST_DB_FILE)
	}
	mysql.DefaultDB = GetDB()
	suite.Run(t, new(VTapTestSuite))
}

func (s *VTapTestSuite) SetupSuite() {
	s.db = mysql.DefaultDB.DB
	for _, val := range getModels() {
		s.db.AutoMigrate(val)
	}
}

func (s *VTapTestSuite) TearDownSuite() {
	sqlDB, _ := s.db.DB()
	sqlDB.Close()
	os.Remove(TEST_DB_FILE)
}

func (s *VTapTestSuite) SetupTest() {
	// Clean up test data (ignore errors if tables don't exist)
	_ = s.db.Exec("DELETE FROM vtap").Error
	_ = s.db.Exec("DELETE FROM vm").Error
	_ = s.db.Exec("DELETE FROM pod_node").Error
	_ = s.db.Exec("DELETE FROM host_device").Error
	_ = s.db.Exec("DELETE FROM pod").Error
	_ = s.db.Exec("DELETE FROM vm_pod_node_connection").Error
}

func GetDB() *mysql.DB {
	gormDB, err := gorm.Open(
		sqlite.Open(TEST_DB_FILE),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	if err != nil {
		fmt.Printf("create sqlite database failed: %s\n", err.Error())
		os.Exit(1)
	}

	sqlDB, _ := gormDB.DB()
	sqlDB.SetMaxIdleConns(50)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Create mysql.DB wrapper
	// Create minimal config for testing
	dbConfig := mysqlconfig.Config{
		Database: "test_db",
		Type:     "SQLite",
	}

	return &mysql.DB{
		DB:             gormDB,
		ORGID:          1,
		Name:           "test_db",
		LogPrefixORGID: logger.NewORGPrefix(1),
		LogPrefixName:  mysql.NewDBNameLogPrefix("test_db"),
		Config:         dbConfig,
	}
}

func getModels() []interface{} {
	return []interface{}{
		&mysqlmodel.VTap{},
		&mysqlmodel.VM{},
		&mysqlmodel.PodNode{},
		&mysqlmodel.Host{},
		&mysqlmodel.Pod{},
		&mysqlmodel.VMPodNodeConnection{},
	}
}

func (s *VTapTestSuite) TestNewVTapCheck() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
		VTapAutoDelete: config.VTapAutoDelete{
			Enabled:     true,
			LostTimeMax: 3600,
		},
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	assert.NotNil(s.T(), check)
	assert.NotNil(s.T(), check.vCtx)
	assert.NotNil(s.T(), check.vCancel)
	assert.Equal(s.T(), cfg, check.cfg)
}

func (s *VTapTestSuite) TestStop() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Test Stop method
	check.Stop()

	// Verify context has been cancelled
	select {
	case <-check.vCtx.Done():
		// Context cancelled, test passed
	default:
		s.T().Error("context should be cancelled after Stop()")
	}
}

func (s *VTapTestSuite) TestLaunchServerCheck_WorkloadV() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Create test data
	vm := mysqlmodel.VM{
		Base: mysqlmodel.Base{
			Lcuuid: uuid.NewString(),
		},
		Name:   "test-vm",
		Region: "test-region",
	}
	s.db.Create(&vm)

	vtap := mysqlmodel.VTap{
		Name:            "old-name",
		Type:            common.VTAP_TYPE_WORKLOAD_V,
		Lcuuid:          vm.Lcuuid,
		LaunchServerID:  0,
		Region:          "old-region",
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
		LaunchServer:    "192.168.1.1",
	}
	s.db.Create(&vtap)

	// Execute check
	db := mysql.DefaultDB
	check.launchServerCheck(db)

	// Verify results
	var updatedVTap mysqlmodel.VTap
	s.db.First(&updatedVTap, vtap.ID)
	assert.Equal(s.T(), vm.ID, updatedVTap.LaunchServerID)
	assert.Equal(s.T(), vm.Region, updatedVTap.Region)
	assert.Contains(s.T(), updatedVTap.Name, "test-vm")
}

func (s *VTapTestSuite) TestLaunchServerCheck_WorkloadV_DeleteWhenVMNotFound() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Create VTap without corresponding VM
	vtap := mysqlmodel.VTap{
		Type:            common.VTAP_TYPE_WORKLOAD_V,
		Name:            "test-vtap",
		Lcuuid:          uuid.NewString(), // Non-existent VM lcuuid
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
		LaunchServer:    "192.168.1.1",
	}
	s.db.Create(&vtap)

	// 执行检查
	db := mysql.DefaultDB
	check.launchServerCheck(db)

	// Verify VTap has been deleted
	var count int64
	s.db.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap.ID).Count(&count)
	assert.Equal(s.T(), int64(0), count)
}

func (s *VTapTestSuite) TestLaunchServerCheck_KVM() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// 创建测试数据
	host := mysqlmodel.Host{
		Base: mysqlmodel.Base{
			Lcuuid: uuid.NewString(),
		},
		Name:   "test-host",
		IP:     "192.168.1.1",
		Region: "test-region",
	}
	s.db.Create(&host)

	vtap := mysqlmodel.VTap{
		Type:            common.VTAP_TYPE_KVM,
		Name:            "old-name",
		LaunchServer:    host.IP,
		LaunchServerID:  0,
		Region:          "old-region",
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
	}
	s.db.Create(&vtap)

	// Execute check
	db := mysql.DefaultDB
	check.launchServerCheck(db)

	// Verify results
	var updatedVTap mysqlmodel.VTap
	s.db.First(&updatedVTap, vtap.ID)
	assert.Equal(s.T(), host.ID, updatedVTap.LaunchServerID)
	assert.Equal(s.T(), host.Region, updatedVTap.Region)
	assert.Contains(s.T(), updatedVTap.Name, "test-host")
}

func (s *VTapTestSuite) TestLaunchServerCheck_ESXI() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// 创建测试数据
	host := mysqlmodel.Host{
		Base: mysqlmodel.Base{
			Lcuuid: uuid.NewString(),
		},
		Name:   "test-host-esxi",
		IP:     "192.168.1.2",
		Region: "test-region",
	}
	s.db.Create(&host)

	vtap := mysqlmodel.VTap{
		Type:            common.VTAP_TYPE_ESXI,
		Name:            "old-name",
		LaunchServer:    host.IP,
		LaunchServerID:  0,
		Region:          "old-region",
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
	}
	s.db.Create(&vtap)

	// Execute check
	db := mysql.DefaultDB
	check.launchServerCheck(db)

	// Verify results
	var updatedVTap mysqlmodel.VTap
	s.db.First(&updatedVTap, vtap.ID)
	assert.Equal(s.T(), host.ID, updatedVTap.LaunchServerID)
	assert.Equal(s.T(), host.Region, updatedVTap.Region)
}

func (s *VTapTestSuite) TestLaunchServerCheck_PodHost() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// 创建测试数据
	podNode := mysqlmodel.PodNode{
		Base: mysqlmodel.Base{

			Lcuuid: uuid.NewString(),
		},
		Name:   "test-podnode",
		Region: "test-region",
	}
	s.db.Create(&podNode)

	vtap := mysqlmodel.VTap{

		Type:            common.VTAP_TYPE_POD_HOST,
		Name:            "old-name",
		Lcuuid:          podNode.Lcuuid,
		LaunchServerID:  0,
		Region:          "old-region",
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
		LaunchServer:    "192.168.1.1",
	}
	s.db.Create(&vtap)

	// Execute check
	db := mysql.DefaultDB
	check.launchServerCheck(db)

	// Verify results
	var updatedVTap mysqlmodel.VTap
	s.db.First(&updatedVTap, vtap.ID)
	assert.Equal(s.T(), podNode.ID, updatedVTap.LaunchServerID)
	assert.Equal(s.T(), podNode.Region, updatedVTap.Region)
	assert.Contains(s.T(), updatedVTap.Name, "test-podnode")
}

func (s *VTapTestSuite) TestLaunchServerCheck_PodVM() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// 创建测试数据
	podNode := mysqlmodel.PodNode{
		Base: mysqlmodel.Base{

			Lcuuid: uuid.NewString(),
		},
		Name:   "test-podnode-vm",
		Region: "test-region",
	}
	s.db.Create(&podNode)

	vtap := mysqlmodel.VTap{

		Type:            common.VTAP_TYPE_POD_VM,
		Name:            "old-name",
		Lcuuid:          podNode.Lcuuid,
		LaunchServerID:  0,
		Region:          "old-region",
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
		LaunchServer:    "192.168.1.1",
	}
	s.db.Create(&vtap)

	// Execute check
	db := mysql.DefaultDB
	check.launchServerCheck(db)

	// Verify results
	var updatedVTap mysqlmodel.VTap
	s.db.First(&updatedVTap, vtap.ID)
	assert.Equal(s.T(), podNode.ID, updatedVTap.LaunchServerID)
	assert.Equal(s.T(), podNode.Region, updatedVTap.Region)
}

func (s *VTapTestSuite) TestLaunchServerCheck_K8sSidecar() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// 创建测试数据
	pod := mysqlmodel.Pod{
		Base: mysqlmodel.Base{

			Lcuuid: uuid.NewString(),
		},
		Name:   "test-pod",
		Region: "test-region",
	}
	s.db.Create(&pod)

	vtap := mysqlmodel.VTap{

		Type:            common.VTAP_TYPE_K8S_SIDECAR,
		Name:            "old-name",
		Lcuuid:          pod.Lcuuid,
		LaunchServerID:  0,
		Region:          "old-region",
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
		LaunchServer:    "192.168.1.1",
	}
	s.db.Create(&vtap)

	// Execute check
	db := mysql.DefaultDB
	check.launchServerCheck(db)

	// Verify results
	var updatedVTap mysqlmodel.VTap
	s.db.First(&updatedVTap, vtap.ID)
	assert.Equal(s.T(), pod.ID, updatedVTap.LaunchServerID)
	assert.Equal(s.T(), pod.Region, updatedVTap.Region)
	assert.Contains(s.T(), updatedVTap.Name, "test-pod")
}

func (s *VTapTestSuite) TestTypeCheck_DeleteWhenHasConnection() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Create test data
	vm := mysqlmodel.VM{
		Base: mysqlmodel.Base{

			Lcuuid: uuid.NewString(),
		},
		HType: common.VM_HTYPE_BM_C,
	}
	s.db.Create(&vm)

	podNode := mysqlmodel.PodNode{
		Base: mysqlmodel.Base{

			Lcuuid: uuid.NewString(),
		},
		IP: "192.168.1.1",
	}
	s.db.Create(&podNode)

	conn := mysqlmodel.VMPodNodeConnection{
		Base: mysqlmodel.Base{
			Lcuuid: uuid.NewString(),
		},
		VMID:      vm.ID,
		PodNodeID: podNode.ID,
	}
	s.db.Create(&conn)

	vtap := mysqlmodel.VTap{

		Type:            common.VTAP_TYPE_WORKLOAD_V,
		Name:            "test-vtap",
		Lcuuid:          vm.Lcuuid,
		LaunchServer:    podNode.IP,
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
	}
	s.db.Create(&vtap)

	// 执行检查
	db := mysql.DefaultDB
	check.typeCheck(db)

	// Verify VTap has been deleted
	var count int64
	s.db.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap.ID).Count(&count)
	assert.Equal(s.T(), int64(0), count)
}

func (s *VTapTestSuite) TestTypeCheck_KeepWhenNoConnection() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Create test data without connection
	vm := mysqlmodel.VM{
		Base: mysqlmodel.Base{

			Lcuuid: uuid.NewString(),
		},
		HType: common.VM_HTYPE_BM_C,
	}
	s.db.Create(&vm)

	vtap := mysqlmodel.VTap{

		Type:            common.VTAP_TYPE_WORKLOAD_V,
		Name:            "test-vtap",
		Lcuuid:          vm.Lcuuid,
		CtrlIP:          "192.168.1.1",
		AnalyzerIP:      "192.168.1.2",
		ControllerIP:    "192.168.1.3",
		CurControllerIP: "192.168.1.3",
		CurAnalyzerIP:   "192.168.1.2",
		LaunchServer:    "192.168.1.1",
	}
	s.db.Create(&vtap)

	// 执行检查
	db := mysql.DefaultDB
	check.typeCheck(db)

	// Verify VTap has not been deleted
	var count int64
	s.db.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap.ID).Count(&count)
	assert.Equal(s.T(), int64(1), count)
}

func (s *VTapTestSuite) TestDeleteLostVTap() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
		VTapAutoDelete: config.VTapAutoDelete{
			Enabled:     true,
			LostTimeMax: 3600, // 1 hour
		},
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Create lost VTap (exceeds max lost time)
	lostTime := time.Now().Add(-2 * time.Hour) // 2 hours ago
	vtap1 := mysqlmodel.VTap{
		Type:               common.VTAP_TYPE_WORKLOAD_V,
		Name:               "lost-vtap",
		SyncedControllerAt: lostTime,
		CtrlIP:             "192.168.1.1",
		CtrlMac:            "00:00:00:00:00:01",
		AnalyzerIP:         "192.168.1.2",
		ControllerIP:       "192.168.1.3",
		CurControllerIP:    "192.168.1.3",
		CurAnalyzerIP:      "192.168.1.2",
		LaunchServer:       "192.168.1.1",
		Lcuuid:             uuid.NewString(), // Add required lcuuid field
	}
	// Create record first
	result := s.db.Create(&vtap1)
	assert.NoError(s.T(), result.Error, "Creating vtap1 should succeed")
	// Then update state to NOT_CONNECTED (0)
	s.db.Model(&vtap1).Update("state", common.VTAP_STATE_NOT_CONNECTED)

	// Create non-lost VTap (within max lost time)
	recentTime := time.Now().Add(-30 * time.Minute) // 30 minutes ago
	vtap2 := mysqlmodel.VTap{
		Type:               common.VTAP_TYPE_WORKLOAD_V,
		Name:               "normal-vtap",
		SyncedControllerAt: recentTime,
		CtrlIP:             "192.168.1.2",
		CtrlMac:            "00:00:00:00:00:02",
		AnalyzerIP:         "192.168.1.2",
		ControllerIP:       "192.168.1.3",
		CurControllerIP:    "192.168.1.3",
		CurAnalyzerIP:      "192.168.1.2",
		LaunchServer:       "192.168.1.2",
		Lcuuid:             uuid.NewString(), // Add required lcuuid field
	}
	s.db.Create(&vtap2)
	// Then update state to NOT_CONNECTED (0)
	s.db.Model(&vtap2).Update("state", common.VTAP_STATE_NOT_CONNECTED)

	// Create DEDICATED type VTap (should not be deleted)
	vtap3 := mysqlmodel.VTap{
		Type:               common.VTAP_TYPE_DEDICATED,
		Name:               "dedicated-vtap",
		SyncedControllerAt: lostTime,
		CtrlIP:             "192.168.1.3",
		CtrlMac:            "00:00:00:00:00:03",
		AnalyzerIP:         "192.168.1.2",
		ControllerIP:       "192.168.1.3",
		CurControllerIP:    "192.168.1.3",
		CurAnalyzerIP:      "192.168.1.2",
		LaunchServer:       "192.168.1.3",
		Lcuuid:             uuid.NewString(), // Add required lcuuid field
	}
	s.db.Create(&vtap3)
	// Then update state to NOT_CONNECTED (0)
	s.db.Model(&vtap3).Update("state", common.VTAP_STATE_NOT_CONNECTED)

	// Execute check
	db := mysql.DefaultDB
	check.deleteLostVTap(db)

	// Verify results
	var count1, count2, count3 int64
	s.db.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap1.ID).Count(&count1)
	s.db.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap2.ID).Count(&count2)
	s.db.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap3.ID).Count(&count3)

	assert.Equal(s.T(), int64(0), count1, "Lost VTap should be deleted")
	assert.Equal(s.T(), int64(1), count2, "Normal VTap should not be deleted")
	assert.Equal(s.T(), int64(1), count3, "DEDICATED type VTap should not be deleted")
}

func (s *VTapTestSuite) TestDeleteLostVTap_EmptyList() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
		VTapAutoDelete: config.VTapAutoDelete{
			Enabled:     true,
			LostTimeMax: 3600,
		},
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Don't create any VTap, test empty list case
	db := mysql.DefaultDB
	check.deleteLostVTap(db)

	// Should execute normally without errors
	var count int64
	s.db.Model(&mysqlmodel.VTap{}).Count(&count)
	assert.Equal(s.T(), int64(0), count)
}

func (s *VTapTestSuite) TestDeleteLostVTap_OnlyNormalState() {
	cfg := config.MonitorConfig{
		VTapCheckInterval: 60,
		VTapAutoDelete: config.VTapAutoDelete{
			Enabled:     true,
			LostTimeMax: 3600,
		},
	}
	ctx := context.Background()
	check := NewVTapCheck(cfg, ctx)

	// Create VTap with normal state (should not be deleted)
	lostTime := time.Now().Add(-2 * time.Hour)
	vtap := mysqlmodel.VTap{

		Type:               common.VTAP_TYPE_WORKLOAD_V,
		Name:               "normal-state-vtap",
		State:              common.VTAP_STATE_NORMAL, // Normal state
		SyncedControllerAt: lostTime,
		CtrlIP:             "192.168.1.1",
		CtrlMac:            "00:00:00:00:00:01",
		AnalyzerIP:         "192.168.1.2",
		ControllerIP:       "192.168.1.3",
		CurControllerIP:    "192.168.1.3",
		CurAnalyzerIP:      "192.168.1.2",
		LaunchServer:       "192.168.1.1",
	}
	s.db.Create(&vtap)

	// 执行检查
	db := mysql.DefaultDB
	check.deleteLostVTap(db)

	// Verify VTap has not been deleted (because state is not NOT_CONNECTED)
	var count int64
	s.db.Model(&mysqlmodel.VTap{}).Where("id = ?", vtap.ID).Count(&count)
	assert.Equal(s.T(), int64(1), count)
}
