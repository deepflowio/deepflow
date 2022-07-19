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
	"io/ioutil"

	"gorm.io/gorm"

	"github.com/deepflowys/deepflow/server/controller/db/mysql/migrate"
)

const (
	DB_VERSION_TABLE  = "db_version"
	DB_VERSION_EXPECT = "6.1.1" // TODO add array to implement step-by-step migration
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
		db.Raw(fmt.Sprintf("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%s'", cfg.Database, DB_VERSION_TABLE)).Scan(&versionTable)
		if versionTable != DB_VERSION_TABLE {
			err = db.Exec(migrate.CREATE_TABLE_DB_VERSION).Error
			if err != nil {
				log.Errorf("create table db_version failed: %v", err)
				return false
			}
		}
		var version string
		err = db.Raw(fmt.Sprintf("SELECT version FROM db_version")).Scan(&version).Error
		if err != nil {
			log.Errorf("check db version failed: %v", err)
			return false
		}
		if versionTable != DB_VERSION_TABLE || (version != "" && version != DB_VERSION_EXPECT) {
			err = executeIssu(db, DB_VERSION_EXPECT)
			if err != nil {
				return false
			}
			err = db.Exec(fmt.Sprintf("UPDATE db_version SET version='%s'", DB_VERSION_EXPECT)).Error
			if err != nil {
				log.Errorf("update db version failed: %v", err)
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
	log.Info("init db tables success")
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
