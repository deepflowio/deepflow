/**
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
	"sync"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql/migration"
)

var (
	DefaultDB *DB

	dbsOnce sync.Once
	dbs     *DBs
)

func GetDB(orgID int) (*DB, error) {
	return GetDBs().NewDBIfNotExists(orgID)
}

func GetConfig() config.MySqlConfig {
	return GetDBs().GetConfig()
}

func InitDefaultDB(cfg config.MySqlConfig) error {
	var err error
	DefaultDB, err = NewDB(cfg, common.DEFAULT_ORG_ID)
	if err != nil {
		return err
	}
	return nil
}

type DB struct {
	*gorm.DB
	ORGID int
	Name  string
}

func NewDB(cfg config.MySqlConfig, orgID int) (*DB, error) {
	var db *gorm.DB
	var err error
	copiedCfg := cfg
	if orgID == common.DEFAULT_ORG_ID {
		db, err = common.GetSession(copiedCfg)
	} else {
		copiedCfg = common.ReplaceConfigDatabaseName(cfg, orgID)
		db, err = common.GetSession(copiedCfg)
	}
	if err != nil {
		log.Errorf("failed to create db session: %s, config: %v", err.Error(), copiedCfg)
		return nil, err
	}
	return &DB{db, orgID, copiedCfg.Database}, nil
}

func (d *DB) PreORGID(format string, a ...any) string { // TODO optimize
	return fmt.Sprintf("[OID-%d] %s", d.ORGID, fmt.Sprintf(format, a...))
}

func (d *DB) GetORGID() int {
	return d.ORGID
}

func (d *DB) GetName() string {
	return d.Name
}

type DBs struct {
	cfg config.MySqlConfig

	mux       sync.Mutex
	orgIDToDB map[int]*DB
}

func GetDBs() *DBs {
	dbsOnce.Do(func() {
		dbs = &DBs{
			orgIDToDB: make(map[int]*DB),
		}
	})
	return dbs
}

func (c *DBs) Init(cfg config.MySqlConfig) error {
	var err error
	c.cfg = cfg
	DefaultDB, err = c.NewDBIfNotExists(common.DEFAULT_ORG_ID)
	if err != nil {
		return err
	}
	orgIDs, err := GetORGIDs()
	if err != nil {
		return err
	}
	for _, id := range orgIDs {
		if _, err := c.NewDBIfNotExists(id); err != nil {
			return err
		}
	}
	return err
}

func (c *DBs) GetConfig() config.MySqlConfig {
	return c.cfg
}

func (c *DBs) NewDBIfNotExists(orgID int) (*DB, error) {
	if db, ok := c.get(orgID); ok {
		return db, nil
	}

	db, err := NewDB(c.cfg, orgID)
	if err != nil {
		return nil, err
	}
	if err := c.check(db); err != nil {
		return nil, err
	}

	c.set(orgID, db)
	return db, nil
}

func (c *DBs) All() []*DB {
	c.mux.Lock()
	defer c.mux.Unlock()
	var dbs []*DB
	for _, db := range c.orgIDToDB {
		dbs = append(dbs, db)
	}
	return dbs
}

func (c *DBs) Delete(orgID int) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.orgIDToDB, orgID)
}

func (c *DBs) Create(orgID int) {
	c.NewDBIfNotExists(orgID)
}

func (c *DBs) get(orgID int) (*DB, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()
	db, ok := c.orgIDToDB[orgID]
	return db, ok
}

func (c *DBs) set(orgID int, db *DB) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.orgIDToDB[orgID] = db
}

func (c *DBs) check(db *DB) error {
	if db.ORGID != common.DEFAULT_ORG_ID {
		return nil
	}
	var version string
	err := db.Raw(fmt.Sprintf("SELECT version FROM db_version")).Scan(&version).Error
	if err != nil {
		log.Errorf("db: %s, failed to check db version: %s", db.Name, err.Error())
		return err
	}
	if version != migration.DB_VERSION_EXPECTED {
		log.Errorf("db: %s, current db version: %s != expected db version: %s", db.Name, version, migration.DB_VERSION_EXPECTED)
		return err
	}
	return nil
}

func (c *DBs) DoOnAllDBs(execFunc func(db *DB) error) error {
	for _, db := range dbs.orgIDToDB {
		if err := execFunc(db); err != nil {
			return fmt.Errorf("org(id:%d, name:%s) %s", db.ORGID, db.Name, err.Error())
		}
	}
	return nil
}
