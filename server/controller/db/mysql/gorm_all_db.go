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

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	. "github.com/deepflowio/deepflow/server/controller/db/mysql/config"
)

var DBMap = &DB{dbMap: make(map[string]*gorm.DB)}

type DB struct {
	dbMap map[string]*gorm.DB // key is database name
	mu    sync.Mutex
}

func (d *DB) Add(dbName string, dbInstance *gorm.DB) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dbMap[dbName] = dbInstance
}

func (d *DB) Get(dbName string) *gorm.DB {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dbMap[dbName]
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
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local&timeout=%ds",
		cfg.UserName,
		cfg.UserPassword,
		cfg.Host,
		cfg.Port,
		cfg.TimeOut*2,
	)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Error(err)
		return err
	}
	rows, err := db.Raw("SHOW DATABASES").Rows()
	if err != nil {
		log.Error(err)
		return err
	}

	var databaseName string
	for rows.Next() {
		rows.Scan(&databaseName)
		// TODO(weiqiang): 待确认，数据库名称前缀
		if strings.HasSuffix(databaseName, "deepflow") {
			DBMap.Add(databaseName, GetConnectionWithDatabase(cfg))
		}
	}
	return nil
}
