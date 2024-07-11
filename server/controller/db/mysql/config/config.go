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

type MySqlConfig struct {
	Database               string `default:"deepflow" yaml:"database"`
	Host                   string `default:"mysql" yaml:"host"`
	Port                   uint32 `default:"30130" yaml:"port"`
	ProxyHost              string `default:"" yaml:"proxy-host"`
	ProxyPort              uint32 `default:"0" yaml:"proxy-port"`
	UserName               string `default:"root" yaml:"user-name"`
	UserPassword           string `default:"deepflow" yaml:"user-password"`
	TimeOut                uint32 `default:"30" yaml:"timeout"`
	DropDatabaseEnabled    bool   `default:"false" yaml:"drop-database-enabled"`
	AutoIncrementIncrement uint32 `default:"1" yaml:"auto_increment_increment"`
	ResultSetMax           uint32 `default:"100000" yaml:"result_set_max"`
	MaxOpenConns           uint16 `default:"100" yaml:"max_open_conns"`
	MaxIdleConns           uint16 `default:"50" yaml:"max_idle_conns"`
	ConnMaxLifeTime        uint16 `default:"60" yaml:"conn_max_life_time"`
}
