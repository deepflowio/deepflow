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

package common

type Swagger struct {
	Enabled bool `default:"true" yaml:"enabled"`
}

type Warrant struct {
	Enabled bool   `default:"false" yaml:"enabled"`
	Host    string `default:"warrant" yaml:"host"`
	Port    int    `default:"20413" yaml:"port"`
	Timeout int    `default:"30" yaml:"timeout"`
}

// TODO use this
type FPermit struct {
	Enabled bool   `default:"false" yaml:"enabled"`
	Host    string `default:"fpermit" yaml:"host"`
	Port    int    `default:"20823" yaml:"port"`
	Timeout int    `default:"30" yaml:"timeout"`
}

type IngesterApi struct {
	Port     int `default:"20106" yaml:"port"`
	NodePort int `default:"30106" yaml:"node-port"`
	Timeout  int `default:"60" yaml:"timeout"`
}
