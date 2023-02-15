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

package kubernetes

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

const (
	TEST_DB_FILE = "test.db"
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
		&mysql.Domain{}, &mysql.SubDomain{},
	}
}

func ClearDBFile(f string) {
	if _, err := os.Stat(f); err == nil {
		os.Remove(f)
	}
}

func TestRefresh(t *testing.T) {
	ClearDBFile(TEST_DB_FILE)
	mysql.Db = GetDB(TEST_DB_FILE)
	for _, val := range GetModels() {
		mysql.Db.AutoMigrate(val)
	}
	domain := mysql.Domain{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String(), Type: 11}
	mysql.Db.Create(&domain)
	subDomain := mysql.SubDomain{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
	mysql.Db.Create(&subDomain)
	k8sInfo := NewKubernetesInfo(mysql.Db, nil)
	k8sInfo.refresh()
	if len(k8sInfo.clusterIDToDomain) != 1 {
		fmt.Println("cluster id domain map is not expected.")
	}
	if len(k8sInfo.clusterIDToSubDomain) != 1 {
		fmt.Println("cluster id sub_domain map is not expected.")
	}
	ClearDBFile(TEST_DB_FILE)
}

func TestCheckDomainSubDomainByClusterID(t *testing.T) {
	ClearDBFile(TEST_DB_FILE)
	mysql.Db = GetDB(TEST_DB_FILE)
	for _, val := range GetModels() {
		mysql.Db.AutoMigrate(val)
	}
	k8sInfo := NewKubernetesInfo(mysql.Db, nil)
	k8sInfo.clusterIDToDomain = map[string]string{"a": "b"}
	k8sInfo.clusterIDToSubDomain = map[string]string{"b": "c"}
	if ok, _ := k8sInfo.CheckClusterID("a"); !ok {
		fmt.Printf("check cluster id: %s should be ok\n", "a")
	}
	if ok, _ := k8sInfo.CheckClusterID("b"); !ok {
		fmt.Printf("check cluster id: %s should be ok\n", "b")
	}
	k8sInfo.clusterIDToDomain = make(map[string]string)
	k8sInfo.clusterIDToSubDomain = make(map[string]string)
	domain := mysql.Domain{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String(), Type: 11, ClusterID: "d"}
	mysql.Db.Create(&domain)
	if ok, _ := k8sInfo.CheckClusterID("d"); !ok {
		fmt.Printf("check cluster id: %s should be ok\n", "a")
	}
	if ok, _ := k8sInfo.CheckClusterID("C"); ok {
		fmt.Printf("check cluster id: %s should not be ok\n", "a")
	}
	ClearDBFile(TEST_DB_FILE)
}
