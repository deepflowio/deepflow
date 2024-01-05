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

import "time"

type ExternalAPM struct {
	Name        string            `yaml:"name"`
	Addr        string            `yaml:"addr"` // e.g.: http://host:port
	Timeout     time.Duration     `default:"60s" yaml:"timeout"`
	TLS         *TLSConfig        `yaml:"tls_config"`
	ExtraConfig map[string]string `yaml:"extra_config"`
}

type TLSConfig struct {
	CAFile   string `yaml:"ca-file"`
	CertFile string `yaml:"cert-file"`
	KeyFile  string `yaml:"key-file"`
	Insecure bool   `yaml:"insecure"`
}
