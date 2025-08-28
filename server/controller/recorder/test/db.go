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

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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
		&metadbmodel.Domain{}, &metadbmodel.Region{}, &metadbmodel.AZ{}, &metadbmodel.SubDomain{}, &metadbmodel.Host{}, &metadbmodel.VM{},
		&metadbmodel.VPC{}, &metadbmodel.Network{}, &metadbmodel.Subnet{}, &metadbmodel.VRouter{}, &metadbmodel.RoutingTable{},
		&metadbmodel.DHCPPort{}, &metadbmodel.VInterface{}, &metadbmodel.WANIP{}, &metadbmodel.LANIP{}, &metadbmodel.FloatingIP{},
		&metadbmodel.LB{},
		&metadbmodel.LBListener{}, &metadbmodel.LBTargetServer{}, &metadbmodel.NATGateway{}, &metadbmodel.NATRule{},
		&metadbmodel.NATVMConnection{}, &metadbmodel.LBVMConnection{}, &metadbmodel.CEN{}, &metadbmodel.PeerConnection{},
		&metadbmodel.RDSInstance{}, &metadbmodel.RedisInstance{},
		&metadbmodel.PodCluster{}, &metadbmodel.PodNode{}, &metadbmodel.PodNamespace{}, &metadbmodel.VMPodNodeConnection{},
		&metadbmodel.PodIngress{}, &metadbmodel.PodIngressRule{}, &metadbmodel.PodIngressRuleBackend{},
		&metadbmodel.PodService{}, &metadbmodel.PodServicePort{}, &metadbmodel.PodGroup{}, &metadbmodel.PodGroupPort{},
		&metadbmodel.PodReplicaSet{}, &metadbmodel.Pod{},
	}
}

func ClearDBData[MT metadbmodel.AssetResourceConstraint](db *gorm.DB) {
	db.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(new(MT))
}
