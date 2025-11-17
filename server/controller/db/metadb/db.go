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

package metadb

import (
	"fmt"
	"sync"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/common"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/config"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/migrator/edition"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/session"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/sqladapter"
	"github.com/deepflowio/deepflow/server/controller/db/metadb/sqladapter/types"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("db.metadb")

var (
	DefaultDB *DB

	dbsOnce sync.Once
	dbs     *DBs
)

func GetDB(orgID int) (*DB, error) {
	return GetDBs().NewDBIfNotExists(orgID)
}

func RemoveDB(orgID int) {
	GetDBs().Delete(orgID)
}

func GetConfig() config.Config {
	return GetDBs().GetConfig()
}

func InitDefaultDB(cfg config.Config) error {
	var err error
	DefaultDB, err = NewDB(cfg, common.DEFAULT_ORG_ID)
	if err != nil {
		return err
	}
	return nil
}

type DB struct {
	*gorm.DB
	ORGID          int
	Name           string
	LogPrefixORGID logger.Prefix
	LogPrefixName  logger.Prefix

	Config config.Config
	SqlFmt types.SQLAdapter
}

func NewDB(cfg config.Config, orgID int) (*DB, error) {
	var db *gorm.DB
	var err error
	copiedCfg := cfg
	if orgID == common.DEFAULT_ORG_ID {
		db, err = session.GetSession(copiedCfg)
	} else {
		copiedCfg = common.ReplaceConfigDatabaseName(cfg, orgID)
		db, err = session.GetSession(copiedCfg)
	}
	if err != nil {
		logConfig := copiedCfg
		logConfig.UserPassword = "******"
		log.Errorf("failed to create db session: %s, config: %#v", err.Error(), logConfig)
		return nil, err
	}
	return &DB{
		db,
		orgID,
		copiedCfg.Database,
		logger.NewORGPrefix(orgID),
		NewDBNameLogPrefix(copiedCfg.Database),
		copiedCfg,
		sqladapter.GetSQLAdapter(copiedCfg),
	}, nil
}

func (d *DB) GetGORMDB() *gorm.DB {
	return d.DB
}

func (d *DB) GetORGID() int {
	return d.ORGID
}

func (d *DB) GetName() string {
	return d.Name
}

type DBs struct {
	cfg config.Config

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

func (c *DBs) Init(cfg config.Config) error {
	var err error
	c.cfg = cfg
	DefaultDB, err = c.NewDBIfNotExists(common.DEFAULT_ORG_ID)
	if err != nil {
		return err
	}
	orgIDs, err := CheckORGNumberAndLog()
	if err != nil {
		return err
	}
	for _, id := range orgIDs {
		if _, err := c.NewDBIfNotExists(id); err != nil {
			log.Errorf("[OID-%d] failed to create db: %s, please check org status", id, err.Error())
		}
	}
	return nil
}

func (c *DBs) GetConfig() config.Config {
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
	return edition.CheckDBVersion(db.DB, db.Config)
}

type DBNameLogPrefix struct {
	Name string
}

func NewDBNameLogPrefix(name string) *DBNameLogPrefix {
	return &DBNameLogPrefix{Name: name}
}

func (n *DBNameLogPrefix) Prefix() string {
	return fmt.Sprintf("[DB-%s] ", n.Name)
}
