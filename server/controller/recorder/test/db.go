/*
 * Copyright (c) 2022 Yunshan Networks
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

package test

import (
	"fmt"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/constraint"
)

func GetDB(dbFile string) *gorm.DB {
	db, err := gorm.Open(
		sqlite.Open(dbFile),
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

func GetModels() []interface{} {
	return []interface{}{
		&mysql.Domain{}, &mysql.Region{}, &mysql.AZ{}, &mysql.SubDomain{}, &mysql.Host{}, &mysql.VM{},
		&mysql.VPC{}, &mysql.Network{}, &mysql.Subnet{}, &mysql.VRouter{}, &mysql.RoutingTable{},
		&mysql.DHCPPort{}, &mysql.VInterface{}, &mysql.WANIP{}, &mysql.LANIP{}, &mysql.FloatingIP{},
		&mysql.SecurityGroup{}, &mysql.SecurityGroupRule{}, &mysql.VMSecurityGroup{}, &mysql.LB{},
		&mysql.LBListener{}, &mysql.LBTargetServer{}, &mysql.NATGateway{}, &mysql.NATRule{},
		&mysql.NATVMConnection{}, &mysql.LBVMConnection{}, &mysql.CEN{}, &mysql.PeerConnection{},
		&mysql.RDSInstance{}, &mysql.RedisInstance{},
		&mysql.PodCluster{}, &mysql.PodNode{}, &mysql.PodNamespace{}, &mysql.VMPodNodeConnection{},
		&mysql.PodIngress{}, &mysql.PodIngressRule{}, &mysql.PodIngressRuleBackend{},
		&mysql.PodService{}, &mysql.PodServicePort{}, &mysql.PodGroup{}, &mysql.PodGroupPort{},
		&mysql.PodReplicaSet{}, &mysql.Pod{},
	}
}

func ClearDBData[MT constraint.MySQLModel](db *gorm.DB) {
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(new(MT))
}
