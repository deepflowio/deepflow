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

package mysql

import (
	"fmt"
	"strings"
	"sync"

	"gorm.io/gorm"

	. "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
)

var DBMap = &DB{dbMap: make(map[string]*gorm.DB)}

type DB struct {
	dbMap map[string]*gorm.DB // key is database name
	mu    sync.Mutex
}

func (d *DB) Add(database string, dbInstance *gorm.DB) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dbMap[database] = dbInstance
}

func (d *DB) Get(database string) (*gorm.DB, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	db, ok := d.dbMap[database]
	if !ok {
		return nil, fmt.Errorf("database(%v) not found", database)
	}
	return db, nil
}

func (d *DB) GetDBMap() map[string]*gorm.DB {
	return d.dbMap
}

func (d *DB) DoTransactionOnAllDBs(execFunc func(db *gorm.DB) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var txs []*gorm.DB
	for _, db := range d.dbMap {
		tx := db.Begin()
		if tx.Error != nil {
			return tx.Error
		}
		txs = append(txs, tx)
	}

	var txErr error
	for _, tx := range txs {
		defer func(t *gorm.DB) {
			if txErr != nil {
				if err := t.Rollback().Error; err != nil {
					log.Error(err)
				}
			}
		}(tx)

		if err := execFunc(tx); err != nil {
			txErr = err
			return err
		}
	}

	for _, tx := range txs {
		if err := tx.Commit().Error; err != nil {
			txErr = err
			return err
		}
	}
	return nil
}

func initMySQLMap(cfg MySqlConfig) error {
	db, err := GetConnectionWithoutDatabase(cfg)
	if err != nil {
		return err
	}
	rows, err := db.Raw("SHOW DATABASES").Rows()
	if err != nil {
		return err
	}

	var databaseName string
	for rows.Next() {
		rows.Scan(&databaseName)

		if strings.HasSuffix(databaseName, "_deepflow") {
			// TODO(weiqiang): fix import cycle
			// if strings.HasSuffix(databaseName, common.DATABASE_SUFFIX) {
			cfg.Database = databaseName
			// TODO(weiqiang): delete
			log.Infof("weiqiang database: %s\n", databaseName)
			gormDB, err := GetConnectionWithDatabase(cfg)
			if err != nil {
				return err
			}
			if gormDB == nil {
				return fmt.Errorf("database(%s) connect mysql failed", databaseName)
			}

			var version string
			err = gormDB.Raw("SELECT version FROM db_version").Scan(&version).Error
			if err != nil {
				return fmt.Errorf("database(%s)  get current db version failed", databaseName)
			}
			if version != migration.DB_VERSION_EXPECTED {
				return fmt.Errorf("database(%s) current db version: %s != expected db version: %s", databaseName, version, migration.DB_VERSION_EXPECTED)
			}
			DBMap.Add(databaseName, gormDB)
		}
	}
	return rows.Close()
}
