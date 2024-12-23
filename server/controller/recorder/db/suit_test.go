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

package db

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/metadb"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

const (
	TEST_DB_FILE = "./db_test.db"
)

type SuiteTest struct {
	suite.Suite
	db *gorm.DB
}

func TestSuite(t *testing.T) {
	if _, err := os.Stat(TEST_DB_FILE); err == nil {
		os.Remove(TEST_DB_FILE)
	}
	metadb.DefaultDB = GetDB()
	suite.Run(t, new(SuiteTest))
}

func (t *SuiteTest) SetupSuite() {
	t.db = metadb.DefaultDB

	for _, val := range getModels() {
		t.db.AutoMigrate(val)
	}
}

func (t *SuiteTest) TearDownSuite() {
	sqlDB, _ := t.db.DB()
	sqlDB.Close()

	os.Remove(TEST_DB_FILE)
}

func GetDB() *gorm.DB {
	db, err := gorm.Open(
		sqlite.Open(TEST_DB_FILE),
		&gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}},
	)
	if err != nil {
		fmt.Printf("create sqlite database failed: %s\n", err.Error())
		os.Exit(1)
	}

	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(50)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	return db
}

func getModels() []interface{} {
	return []interface{}{
		&metadbmodel.Region{}, &metadbmodel.AZ{}, &metadbmodel.SubDomain{}, &metadbmodel.Host{}, &metadbmodel.VM{},
		&metadbmodel.VPC{}, &metadbmodel.Network{}, &metadbmodel.Subnet{}, &metadbmodel.VRouter{}, &metadbmodel.RoutingTable{},
		&metadbmodel.DHCPPort{}, &metadbmodel.VInterface{}, &metadbmodel.WANIP{}, &metadbmodel.LANIP{}, &metadbmodel.FloatingIP{},
		&metadb.SecurityGroup{}, &metadb.SecurityGroupRule{}, &metadb.VMSecurityGroup{}, &metadbmodel.LB{},
		&metadbmodel.LBListener{}, &metadbmodel.LBTargetServer{}, &metadbmodel.NATGateway{}, &metadbmodel.NATRule{},
		&metadbmodel.NATVMConnection{}, &metadbmodel.LBVMConnection{}, &metadbmodel.CEN{}, &metadbmodel.PeerConnection{},
		&metadbmodel.RDSInstance{}, &metadbmodel.RedisInstance{},
		&metadbmodel.PodCluster{}, &metadbmodel.PodNode{}, &metadbmodel.PodNamespace{}, &metadbmodel.VMPodNodeConnection{},
		&metadbmodel.PodIngress{}, &metadbmodel.PodIngressRule{}, &metadbmodel.PodIngressRuleBackend{},
		&metadbmodel.PodService{}, &metadbmodel.PodServicePort{}, &metadbmodel.PodGroup{}, &metadbmodel.PodGroupPort{},
		&metadbmodel.PodReplicaSet{}, &metadbmodel.Pod{},
	}
}

func clearDBData[MT constraint.MySQLModel](db *gorm.DB) {
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(new(MT))
}
