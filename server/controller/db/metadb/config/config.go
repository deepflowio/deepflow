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
	TimeOut      uint32

	// PostgreSQL
	Schema string

	// MySQL
	AutoIncrementIncrement uint32

	DropDatabaseEnabled bool
	MaxOpenConns        uint16
	MaxIdleConns        uint16
	ConnMaxLifeTime     uint16
	BatchSize0          uint32
	BatchSize1          uint32
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
	c.Type = MetaDBTypeMySQL
	c.Database = mysqlCfg.Database
	c.Host = mysqlCfg.Host
	c.Port = mysqlCfg.Port
	c.ProxyHost = mysqlCfg.ProxyHost
	c.ProxyPort = mysqlCfg.ProxyPort
	c.UserName = mysqlCfg.UserName
	c.UserPassword = mysqlCfg.UserPassword
	c.TimeOut = mysqlCfg.TimeOut
	c.AutoIncrementIncrement = mysqlCfg.AutoIncrementIncrement
	c.DropDatabaseEnabled = mysqlCfg.DropDatabaseEnabled
	c.MaxOpenConns = mysqlCfg.MaxOpenConns
	c.MaxIdleConns = mysqlCfg.MaxIdleConns
	c.ConnMaxLifeTime = mysqlCfg.ConnMaxLifeTime
	c.BatchSize0 = mysqlCfg.BatchSize0
	c.BatchSize1 = mysqlCfg.BatchSize1
}

func (c *Config) InitFromPostgreSQL(postgreSQLCfg PostgreSQLConfig) {
	if !postgreSQLCfg.Enabled {
		return
	}
	c.Type = MetaDBTypePostgreSQL
	c.Database = postgreSQLCfg.Database
	c.Schema = postgreSQLCfg.Schema
	c.Host = postgreSQLCfg.Host
	c.Port = postgreSQLCfg.Port
	c.ProxyHost = postgreSQLCfg.ProxyHost
	c.ProxyPort = postgreSQLCfg.ProxyPort
	c.UserName = postgreSQLCfg.UserName
	c.UserPassword = postgreSQLCfg.UserPassword
	c.TimeOut = postgreSQLCfg.TimeOut
	c.DropDatabaseEnabled = postgreSQLCfg.DropDatabaseEnabled
	c.MaxOpenConns = postgreSQLCfg.MaxOpenConns
	c.MaxIdleConns = postgreSQLCfg.MaxIdleConns
	c.ConnMaxLifeTime = postgreSQLCfg.ConnMaxLifeTime
	c.BatchSize0 = postgreSQLCfg.BatchSize0
	c.BatchSize1 = postgreSQLCfg.BatchSize1
}

type MySQLConfig struct {
	Enabled                bool   `default:"true" yaml:"enabled"`
	Database               string `default:"deepflow" yaml:"database"`
	Host                   string `default:"mysql" yaml:"host"`
	Port                   uint32 `default:"30130" yaml:"port"`
	ProxyHost              string `default:"" yaml:"proxy-host"`
	ProxyPort              uint32 `default:"0" yaml:"proxy-port"`
	UserName               string `default:"root" yaml:"user-name"`
	UserPassword           string `default:"deepflow" yaml:"user-password"`
	TimeOut                uint32 `default:"30" yaml:"timeout"`
	AutoIncrementIncrement uint32 `default:"1" yaml:"auto_increment_increment"`
	DropDatabaseEnabled    bool   `default:"false" yaml:"drop-database-enabled"`
	MaxOpenConns           uint16 `default:"100" yaml:"max_open_conns"`
	MaxIdleConns           uint16 `default:"50" yaml:"max_idle_conns"`
	ConnMaxLifeTime        uint16 `default:"60" yaml:"conn_max_life_time"`
	BatchSize0             uint32 `default:"100000" yaml:"batch-size-0"`
	BatchSize1             uint32 `default:"2500" yaml:"batch-size-1"`
}

type PostgreSQLConfig struct {
	Enabled             bool   `default:"false" yaml:"enabled"`
	Database            string `default:"deepflow" yaml:"database"`
	Schema              string `default:"public" yaml:"schema"`
	Host                string `default:"postgresql" yaml:"host"`
	Port                uint32 `default:"5432" yaml:"port"`
	ProxyHost           string `default:"" yaml:"proxy-host"`
	ProxyPort           uint32 `default:"0" yaml:"proxy-port"`
	UserName            string `default:"root" yaml:"user-name"`
	UserPassword        string `default:"deepflow" yaml:"user-password"`
	TimeOut             uint32 `default:"30" yaml:"timeout"`
	DropDatabaseEnabled bool   `default:"false" yaml:"drop-database-enabled"`
	MaxOpenConns        uint16 `default:"100" yaml:"max-open-conns"`
	MaxIdleConns        uint16 `default:"50" yaml:"max-idle-conns"`
	ConnMaxLifeTime     uint16 `default:"60" yaml:"conn-max-life-time"`
	BatchSize0          uint32 `default:"100000" yaml:"batch-size-0"`
	BatchSize1          uint32 `default:"2500" yaml:"batch-size-1"`
}
