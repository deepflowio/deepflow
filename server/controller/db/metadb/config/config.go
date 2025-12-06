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

package config

const (
	MetaDBTypeMySQL      = "MySQL"
	MetaDBTypePostgreSQL = "PostgreSQL"
	MetaDBTypeDM         = "DM"
)

type Config struct {
	Type string

	Database     string
	Host         string
	Port         uint32
	ProxyHost    string
	ProxyPort    uint32
	UserName     string
	UserPassword string
	TimeOut      uint16

	DropDatabaseEnabled bool
	MaxOpenConns        uint16
	MaxIdleConns        uint16
	ConnMaxLifeTime     uint16
	BatchSize0          uint32
	BatchSize1          uint32

	// PostgreSQL
	Schema string

	// MySQL
	AutoIncrementIncrement uint32

	// DM
	DSN string
}

func (c Config) GetAutoIncrementIncrement() uint32 {
	if c.Type == MetaDBTypeMySQL {
		return c.AutoIncrementIncrement
	}
	return 1
}

func (c *Config) InitFromMySQL(mysqlCfg MySQLConfig) {
	if !mysqlCfg.Enabled {
		return
	}
	mysqlCfg.FullfillConfig(c)
}

func (c *Config) InitFromPostgreSQL(postgreSQLCfg PostgreSQLConfig) {
	if !postgreSQLCfg.Enabled {
		return
	}
	postgreSQLCfg.FullfillConfig(c)
}

func (c *Config) InitFromDaMeng(dmCfg DMConfig) {
	if !dmCfg.Enabled {
		return
	}
	dmCfg.FullfillConfig(c)
}

type commonConfig struct {
	UserName     string `default:"root" yaml:"user-name"`
	UserPassword string `default:"deepflow" yaml:"user-password"`

	TimeOut             uint16 `default:"30" yaml:"timeout"`
	DropDatabaseEnabled bool   `default:"false" yaml:"drop-database-enabled"`
	MaxOpenConns        uint16 `default:"100" yaml:"max_open_conns"`
	MaxIdleConns        uint16 `default:"50" yaml:"max_idle_conns"`
	ConnMaxLifeTime     uint16 `default:"60" yaml:"conn_max_life_time"`
	BatchSize0          uint32 `default:"100000" yaml:"batch-size-0"`
	BatchSize1          uint32 `default:"2500" yaml:"batch-size-1"`
}

func (c commonConfig) fullfillConfig(cfg *Config) {
	cfg.UserName = c.UserName
	cfg.UserPassword = c.UserPassword
	cfg.TimeOut = c.TimeOut
	cfg.DropDatabaseEnabled = c.DropDatabaseEnabled
	cfg.MaxOpenConns = c.MaxOpenConns
	cfg.MaxIdleConns = c.MaxIdleConns
	cfg.ConnMaxLifeTime = c.ConnMaxLifeTime
	cfg.BatchSize0 = c.BatchSize0
	cfg.BatchSize1 = c.BatchSize1
}

type MySQLConfig struct {
	Enabled                bool   `default:"true" yaml:"enabled"`
	Database               string `default:"deepflow" yaml:"database"`
	Host                   string `default:"mysql" yaml:"host"`
	Port                   uint32 `default:"30130" yaml:"port"`
	ProxyHost              string `default:"" yaml:"proxy-host"`
	ProxyPort              uint32 `default:"0" yaml:"proxy-port"`
	AutoIncrementIncrement uint32 `default:"1" yaml:"auto_increment_increment"`
	// commonConfig
	UserName     string `default:"root" yaml:"user-name"`
	UserPassword string `default:"deepflow" yaml:"user-password"`

	TimeOut             uint16 `default:"30" yaml:"timeout"`
	DropDatabaseEnabled bool   `default:"false" yaml:"drop-database-enabled"`
	MaxOpenConns        uint16 `default:"100" yaml:"max_open_conns"`
	MaxIdleConns        uint16 `default:"50" yaml:"max_idle_conns"`
	ConnMaxLifeTime     uint16 `default:"60" yaml:"conn_max_life_time"`
	BatchSize0          uint32 `default:"100000" yaml:"batch-size-0"`
	BatchSize1          uint32 `default:"2500" yaml:"batch-size-1"`
}

func (c MySQLConfig) FullfillConfig(cfg *Config) {
	// c.fullfillConfig(cfg)
	cfg.UserName = c.UserName
	cfg.UserPassword = c.UserPassword
	cfg.TimeOut = c.TimeOut
	cfg.DropDatabaseEnabled = c.DropDatabaseEnabled
	cfg.MaxOpenConns = c.MaxOpenConns
	cfg.MaxIdleConns = c.MaxIdleConns
	cfg.ConnMaxLifeTime = c.ConnMaxLifeTime
	cfg.BatchSize0 = c.BatchSize0
	cfg.BatchSize1 = c.BatchSize1

	cfg.Type = MetaDBTypeMySQL
	cfg.Database = c.Database
	cfg.Host = c.Host
	cfg.Port = c.Port
	cfg.ProxyHost = c.ProxyHost
	cfg.ProxyPort = c.ProxyPort
	cfg.AutoIncrementIncrement = c.AutoIncrementIncrement
}

type PostgreSQLConfig struct {
	Enabled   bool   `default:"false" yaml:"enabled"`
	Database  string `default:"deepflow" yaml:"database"`
	Schema    string `default:"public" yaml:"schema"`
	Host      string `default:"postgresql" yaml:"host"`
	Port      uint32 `default:"5432" yaml:"port"`
	ProxyHost string `default:"" yaml:"proxy-host"`
	ProxyPort uint32 `default:"0" yaml:"proxy-port"`
	// commonConfig
	UserName     string `default:"root" yaml:"user-name"`
	UserPassword string `default:"deepflow" yaml:"user-password"`

	TimeOut             uint16 `default:"30" yaml:"timeout"`
	DropDatabaseEnabled bool   `default:"false" yaml:"drop-database-enabled"`
	MaxOpenConns        uint16 `default:"100" yaml:"max_open_conns"`
	MaxIdleConns        uint16 `default:"50" yaml:"max_idle_conns"`
	ConnMaxLifeTime     uint16 `default:"60" yaml:"conn_max_life_time"`
	BatchSize0          uint32 `default:"100000" yaml:"batch-size-0"`
	BatchSize1          uint32 `default:"2500" yaml:"batch-size-1"`
}

func (c PostgreSQLConfig) FullfillConfig(cfg *Config) {
	// c.fullfillConfig(cfg)
	cfg.UserName = c.UserName
	cfg.UserPassword = c.UserPassword
	cfg.TimeOut = c.TimeOut
	cfg.DropDatabaseEnabled = c.DropDatabaseEnabled
	cfg.MaxOpenConns = c.MaxOpenConns
	cfg.MaxIdleConns = c.MaxIdleConns
	cfg.ConnMaxLifeTime = c.ConnMaxLifeTime
	cfg.BatchSize0 = c.BatchSize0
	cfg.BatchSize1 = c.BatchSize1

	cfg.Type = MetaDBTypePostgreSQL
	cfg.Database = c.Database
	cfg.Schema = c.Schema
	cfg.Host = c.Host
	cfg.Port = c.Port
	cfg.ProxyHost = c.ProxyHost
	cfg.ProxyPort = c.ProxyPort
}

type DMConfig struct {
	Enabled   bool   `default:"false" yaml:"enabled"`
	Schema    string `default:"deepflow" yaml:"schema"`
	Host      string `default:"dameng" yaml:"host"`
	Port      uint32 `default:"5236" yaml:"port"`
	ProxyHost string `default:"" yaml:"proxy-host"`
	ProxyPort uint32 `default:"0" yaml:"proxy-port"`
	// commonConfig
	UserName     string `default:"root" yaml:"user-name"`
	UserPassword string `default:"deepflow" yaml:"user-password"`

	DSN                 string `default:"" yaml:"dsn"`
	TimeOut             uint16 `default:"30" yaml:"timeout"`
	DropDatabaseEnabled bool   `default:"false" yaml:"drop-database-enabled"`
	MaxOpenConns        uint16 `default:"100" yaml:"max_open_conns"`
	MaxIdleConns        uint16 `default:"50" yaml:"max_idle_conns"`
	ConnMaxLifeTime     uint16 `default:"60" yaml:"conn_max_life_time"`
	BatchSize0          uint32 `default:"100000" yaml:"batch-size-0"`
	BatchSize1          uint32 `default:"2500" yaml:"batch-size-1"`
}

func (c DMConfig) FullfillConfig(cfg *Config) {
	// c.fullfillConfig(cfg)
	cfg.UserName = c.UserName
	cfg.UserPassword = c.UserPassword
	cfg.TimeOut = c.TimeOut
	cfg.DropDatabaseEnabled = c.DropDatabaseEnabled
	cfg.MaxOpenConns = c.MaxOpenConns
	cfg.MaxIdleConns = c.MaxIdleConns
	cfg.ConnMaxLifeTime = c.ConnMaxLifeTime
	cfg.BatchSize0 = c.BatchSize0
	cfg.BatchSize1 = c.BatchSize1

	cfg.DSN = c.DSN
	cfg.Type = MetaDBTypeDM
	cfg.Database = c.Schema
	cfg.Host = c.Host
	cfg.Port = c.Port
	cfg.ProxyHost = c.ProxyHost
	cfg.ProxyPort = c.ProxyPort
}
