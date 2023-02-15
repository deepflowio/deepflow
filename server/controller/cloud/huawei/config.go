/*
 * Copyright (c) 2022 Yunshan Networks
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

package huawei

import (
	"strings"

	"github.com/bitly/go-simplejson"

	"github.com/deepflowio/deepflow/server/controller/common"
)

type Config struct {
	RegionLcuuid   string
	AccountName    string
	ProjectID      string
	ProjectName    string
	IAMName        string
	Password       string
	ExcludeRegions []string
	IncludeRegions []string

	// 用于API访问，需与DeepFlow自身domain做区分
	URLDomain string
}

func (c *Config) LoadFromString(sConf string) (err error) {
	jConf, err := simplejson.NewJson([]byte(sConf))
	if err != nil {
		log.Error("convert config string: %s to json failed: %v", sConf, err)
		return
	}
	pswd, err := jConf.Get("password").String()
	if err != nil {
		log.Error("password must be specified")
		return
	}
	dpswd, err := common.DecryptSecretKey(pswd)
	if err != nil {
		log.Error("decrypt password failed")
		return
	}
	c.Password = dpswd
	c.AccountName, err = jConf.Get("account_name").String()
	if err != nil {
		log.Error("account_name must be specified")
		return
	}
	c.IAMName, err = jConf.Get("iam_name").String()
	if err != nil {
		log.Error("iam_name must be specified")
		return
	}
	c.ProjectID, err = jConf.Get("project_id").String()
	if err != nil {
		log.Error("project_id must be specified")
		return
	}
	c.ProjectName, err = jConf.Get("region_name").String()
	if err != nil {
		log.Error("region_name must be specified")
		return
	}
	c.RegionLcuuid, err = jConf.Get("region_uuid").String()
	if err != nil {
		log.Error("region_uuid must be specified")
		return
	}
	eRegions := jConf.Get("exclude_regions").MustString()
	if eRegions != "" {
		c.ExcludeRegions = strings.Split(eRegions, ",")
	}
	iRegions := jConf.Get("include_regions").MustString()
	if iRegions != "" {
		c.IncludeRegions = strings.Split(iRegions, ",")
	}
	return
}
