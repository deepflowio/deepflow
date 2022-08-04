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

package mysql

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/deepflowys/deepflow/server/controller/db/mysql/migrate"
)

// if database not exist, create database and tables;
// if database exsits, execute issue if version table not exists or db version not equal lastest version
func Migrate(cfg MySqlConfig) bool {
	dsn := getDSN(cfg, "", cfg.TimeOut, false)
	db := getGormDB(dsn)
	existed, err := createDatabaseIfNotExists(db, cfg.Database)
	if err != nil {
		log.Errorf("database: %s not exists", cfg.Database)
		return false
	}

	// set multiStatements=true in dsn only when migrating MySQL
	dsn = getDSN(cfg, cfg.Database, cfg.TimeOut*2, true)
	db = getGormDB(dsn)
	if !existed {
		err := initTables(db)
		if err != nil {
			db.Exec(fmt.Sprintf("DROP DATABASE %s", cfg.Database))
			return false
		}
	} else {
		var versionTable string
		db.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", cfg.Database, migrate.DB_VERSION_TABLE)).Scan(&versionTable)
		// db_version table not exists, create table, excute all issus
		if versionTable != migrate.DB_VERSION_TABLE {
			err = db.Exec(migrate.CREATE_TABLE_DB_VERSION).Error
			if err != nil {
				log.Errorf("create table db_version failed: %v", err)
				return false
			}
			err = executeIssus(db, "")
			if err != nil {
				return false
			}
		} else {
			var version string
			err = db.Raw(fmt.Sprintf("SELECT version FROM db_version")).Scan(&version).Error
			if err != nil {
				log.Errorf("check db version failed: %v", err)
				return false
			}
			// version value is not latest, excute issus between current and latest version
			if version == "" {
				curVersion := "6.1.1.0"
				err = db.Exec(fmt.Sprintf("INSERT INTO db_version (version) VALUE ('%s')", curVersion)).Error
				if err != nil {
					log.Errorf("init db version failed: %v", err)
					return false
				}
				err = executeIssus(db, curVersion)
			} else {
				err = executeIssus(db, version)
			}
			if err != nil {
				return false
			}
		}
	}
	return true
}

func createDatabaseIfNotExists(db *gorm.DB, database string) (bool, error) {
	var datadbaseName string
	db.Raw(fmt.Sprintf("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='%s'", database)).Scan(&datadbaseName)
	if datadbaseName == database {
		var vmTable string
		db.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", database, "vm")).Scan(&vmTable)
		if vmTable != "vm" {
			return false, nil
		}
		return true, nil
	} else {
		err := db.Exec(fmt.Sprintf("CREATE DATABASE %s", database)).Error
		return false, err
	}
}

func initTables(db *gorm.DB) error {
	initSQL, err := ioutil.ReadFile("/etc/mysql/init.sql")
	if err != nil {
		log.Errorf("read sql file failed: %v", err)
		return err
	}
	err = db.Exec(string(initSQL)).Error
	if err != nil {
		log.Errorf("init db tables failed: %v", err)
		return err
	}
	err = db.Exec(migrate.DROP_PROCEDURE).Error
	if err != nil {
		log.Errorf("drop procedure failed: %v", err)
		return err
	}
	err = db.Exec(migrate.CREATE_PROCDURE).Error
	if err != nil {
		log.Errorf("create procedure failed: %v", err)
		return err
	}
	err = db.Exec(migrate.CREATE_TRIGGER_RESOURCE_GROUP).Error
	if err != nil {
		log.Errorf("create trigger failed: %v", err)
		return err
	}
	err = db.Exec(migrate.CREATE_TRIGGER_NPB_TUNNEL).Error
	if err != nil {
		log.Errorf("create trigger failed: %v", err)
		return err
	}
	err = db.Exec(fmt.Sprintf("INSERT INTO db_version (version) VALUE ('%s')", migrate.DB_VERSION_EXPECT)).Error
	if err != nil {
		log.Errorf("init db version failed: %v", err)
		return err
	}
	log.Info("init db tables success")
	return err
}

func executeIssus(db *gorm.DB, curVersion string) error {
	issus, err := ioutil.ReadDir("/etc/mysql/issu")
	if err != nil {
		log.Errorf("read sql dir faild: %v", err)
		return err
	}
	nextVersions := getAscSortedNextVersions(issus, curVersion)
	for _, nv := range nextVersions {
		err = executeIssu(db, nv)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeIssu(db *gorm.DB, nextVersion string) error {
	issuSQL, err := ioutil.ReadFile(fmt.Sprintf("/etc/mysql/issu/%s.sql", nextVersion))
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
