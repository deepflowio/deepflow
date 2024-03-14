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

package common

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration/script"
)

var log = logging.MustGetLogger("db.mysql.migrator.common")

func DropDatabase(db *gorm.DB, database string) error {
	log.Infof("drop database %s", database)
	return db.Exec(fmt.Sprintf("DROP DATABASE %s", database)).Error
}

func CreateDatabase(db *gorm.DB, database string) error {
	log.Infof("create database %s", database)
	return db.Exec(fmt.Sprintf("CREATE DATABASE %s", database)).Error
}

func CreateDatabaseIfNotExists(db *gorm.DB, database string) (bool, error) {
	var datadbaseName string
	db.Raw(fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'", database)).Scan(&datadbaseName)
	if datadbaseName == database {
		return true, nil
	} else {
		err := CreateDatabase(db, database)
		return false, err
	}
}

func InitEETables(db *gorm.DB) error {
	log.Info("init CE tables start")
	initSQL, err := ioutil.ReadFile(fmt.Sprintf("%s/init.sql", SQL_FILE_DIR))
	if err != nil {
		log.Errorf("read sql file failed: %v", err)
		return err
	}
	err = db.Exec(string(initSQL)).Error
	if err != nil {
		log.Errorf("init db tables failed: %v", err)
		return err
	}
	log.Info("init CE tables success")
	return err
}

func InitDBVersion(db *gorm.DB) error {
	err := db.Exec(fmt.Sprintf("INSERT INTO db_version (version) VALUE ('%s')", migration.DB_VERSION_EXPECTED)).Error
	if err != nil {
		log.Errorf("init db version failed: %v", err)
	}
	return err
}

func ExecuteIssus(db *gorm.DB, curVersion string) error {
	issus, err := ioutil.ReadDir(fmt.Sprintf("%s/issu", SQL_FILE_DIR))
	if err != nil {
		log.Errorf("read sql dir faild: %v", err)
		return err
	}
	nextVersions := getAscSortedNextVersions(issus, curVersion)
	log.Infof("issus to be executed: %v", nextVersions)
	for _, nv := range nextVersions {
		err = executeIssu(db, nv)
		if err != nil {
			return err
		}
		err = executeScript(db, nv)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeIssu(db *gorm.DB, nextVersion string) error {
	issuSQL, err := ioutil.ReadFile(fmt.Sprintf("%s/issu/%s.sql", SQL_FILE_DIR, nextVersion))
	if err != nil {
		log.Errorf("read sql file (version: %s) failed: %v", nextVersion, err)
		return err
	}
	if len(issuSQL) == 0 {
		log.Infof("issu with no content (version: %s)", nextVersion)
		return nil
	}
	err = db.Exec(string(issuSQL)).Error
	if err != nil {
		log.Errorf("excute db issu (version: %s) failed: %v", nextVersion, err)
		return err
	}
	log.Infof("execute db issu (version: %s) success", nextVersion)
	return nil
}

func executeScript(db *gorm.DB, nextVersion string) error {
	var err error
	switch nextVersion {
	case script.SCRIPT_UPDATE_CLOUD_TAG:
		err = script.ScriptUpdateCloudTags(db)
	case script.SCRIPT_UPDATE_VM_PODNS_TAG:
		err = script.ScriptUpdateVMPodNSTags(db)
	}
	return err
}

func getAscSortedNextVersions(files []fs.FileInfo, curVersion string) []string {
	vs := []string{}
	for _, f := range files {
		vs = append(vs, trimFilenameExt(f.Name()))
	}
	// asc sort: split version by ".", compare each number from first to end
	sort.Slice(vs, func(i, j int) bool {
		il := strings.Split(vs[i], ".")
		jl := strings.Split(vs[j], ".")
		return !list1GreaterList2(il, jl)
	})

	nvs := []string{}
	cvl := strings.Split(curVersion, ".")
	for _, v := range vs {
		vl := strings.Split(v, ".")
		if list1GreaterList2(vl, cvl) {
			nvs = append(nvs, v)
		}
	}
	return nvs
}

func trimFilenameExt(filename string) string {
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

func list1GreaterList2(strList1, strList2 []string) bool {
	for i := range strList1 {
		if strList1[i] == strList2[i] {
			continue
		} else {
			in, _ := strconv.Atoi(strList1[i])
			jn, _ := strconv.Atoi(strList2[i])
			return in > jn
		}
	}
	return false
}
