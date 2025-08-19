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

package test

import (
	"fmt"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
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
		&mysqlmodel.Domain{}, &mysqlmodel.Region{}, &mysqlmodel.AZ{}, &mysqlmodel.SubDomain{}, &mysqlmodel.Host{}, &mysqlmodel.VM{},
		&mysqlmodel.VPC{}, &mysqlmodel.Network{}, &mysqlmodel.Subnet{}, &mysqlmodel.VRouter{}, &mysqlmodel.RoutingTable{},
		&mysqlmodel.DHCPPort{}, &mysqlmodel.VInterface{}, &mysqlmodel.WANIP{}, &mysqlmodel.LANIP{}, &mysqlmodel.FloatingIP{},
		&mysqlmodel.LB{},
		&mysqlmodel.LBListener{}, &mysqlmodel.LBTargetServer{}, &mysqlmodel.NATGateway{}, &mysqlmodel.NATRule{},
		&mysqlmodel.NATVMConnection{}, &mysqlmodel.LBVMConnection{}, &mysqlmodel.CEN{}, &mysqlmodel.PeerConnection{},
		&mysqlmodel.RDSInstance{}, &mysqlmodel.RedisInstance{},
		&mysqlmodel.PodCluster{}, &mysqlmodel.PodNode{}, &mysqlmodel.PodNamespace{}, &mysqlmodel.VMPodNodeConnection{},
		&mysqlmodel.PodIngress{}, &mysqlmodel.PodIngressRule{}, &mysqlmodel.PodIngressRuleBackend{},
		&mysqlmodel.PodService{}, &mysqlmodel.PodServicePort{}, &mysqlmodel.PodGroup{}, &mysqlmodel.PodGroupPort{},
		&mysqlmodel.PodReplicaSet{}, &mysqlmodel.Pod{},
	}
}

func ClearDBData[MT mysqlmodel.AssetResourceConstraint](db *gorm.DB) {
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(new(MT))
}
