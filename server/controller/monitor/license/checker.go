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

package license

import (
	"sync"

	configs "github.com/deepflowio/deepflow/server/controller/config/common"
	"github.com/deepflowio/deepflow/server/controller/monitor"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

var (
	checkerOnce sync.Once
	checker     *Checker
)

type Checker struct{}

func BuildChecker() *Checker {
	checkerOnce.Do(func() {
		checker = &Checker{}
	})
	return checker
}

func GetChecker() monitor.LicenseChecker {
	return checker
}

func (c *Checker) Init(cfg configs.Warrant) {
}

func (c *Checker) Check(function int) error {
	return nil
}

func (c *Checker) CheckAgent(agent *metadbmodel.VTap, function int) error {
	return nil
}
