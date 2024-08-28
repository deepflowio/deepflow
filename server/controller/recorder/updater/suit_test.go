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

package updater

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

const (
	TEST_DB_FILE = "./updater_test.db"
)

type SuiteTest struct {
	suite.Suite
	db *gorm.DB
}

func TestSuite(t *testing.T) {
	if _, err := os.Stat(TEST_DB_FILE); err == nil {
		os.Remove(TEST_DB_FILE)
	}
	mysql.DefaultDB = GetDB()
	suite.Run(t, new(SuiteTest))
}

func (t *SuiteTest) SetupSuite() {
	t.db = mysql.DefaultDB
	for _, val := range getMySQLModels() {
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

func getMySQLModels() []interface{} {
	return []interface{}{
		&mysqlmodel.Region{}, &mysqlmodel.AZ{}, &mysqlmodel.SubDomain{}, &mysqlmodel.Host{}, &mysqlmodel.VM{},
		&mysqlmodel.VPC{}, &mysqlmodel.Network{}, &mysqlmodel.Subnet{}, &mysqlmodel.VRouter{}, &mysqlmodel.RoutingTable{},
		&mysqlmodel.DHCPPort{}, &mysqlmodel.VInterface{}, &mysqlmodel.WANIP{}, &mysqlmodel.LANIP{}, &mysqlmodel.FloatingIP{},
		&mysql.SecurityGroup{}, &mysql.SecurityGroupRule{}, &mysql.VMSecurityGroup{}, &mysqlmodel.LB{},
		&mysqlmodel.LBListener{}, &mysqlmodel.LBTargetServer{}, &mysqlmodel.NATGateway{}, &mysqlmodel.NATRule{},
		&mysqlmodel.NATVMConnection{}, &mysqlmodel.LBVMConnection{}, &mysqlmodel.CEN{}, &mysqlmodel.PeerConnection{},
		&mysqlmodel.RDSInstance{}, &mysqlmodel.RedisInstance{},
		&mysqlmodel.PodCluster{}, &mysqlmodel.PodNode{}, &mysqlmodel.PodNamespace{}, &mysqlmodel.VMPodNodeConnection{},
		&mysqlmodel.PodIngress{}, &mysqlmodel.PodIngressRule{}, &mysqlmodel.PodIngressRuleBackend{},
		&mysqlmodel.PodService{}, &mysqlmodel.PodServicePort{}, &mysqlmodel.PodGroup{}, &mysqlmodel.PodGroupPort{},
		&mysqlmodel.PodReplicaSet{}, &mysqlmodel.Pod{}, &mysqlmodel.Process{},
	}
}

func randID() int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(999)
}
