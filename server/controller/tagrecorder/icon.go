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

package tagrecorder

import (
	"errors"
	"fmt"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type IconData struct {
	ID   int
	Name string
}

type IconKey struct {
	NodeType string
	SubType  int
}

func ParseIcon(cfg config.ControllerConfig, response *simplejson.Json) (map[string]int, map[IconKey]int, error) {
	domainToIconID := make(map[string]int)
	resourceToIconID := make(map[IconKey]int)
	if len(response.Get("DATA").MustArray()) == 0 {
		return domainToIconID, resourceToIconID, errors.New("no data in get icons response")
	}
	Icons := []IconData{}
	for i, _ := range response.Get("DATA").MustArray() {
		data := response.Get("DATA").GetIndex(i)
		for k, _ := range IconNameToDomainType {
			if data.Get("NAME").MustString() == k {
				var iconData IconData
				iconData.Name = data.Get("NAME").MustString()
				iconData.ID = data.Get("ID").MustInt()
				Icons = append(Icons, iconData)
			}
		}
		if data.Get("NODE_TYPE").MustString() == "" || data.Get("ID").MustInt() == 0 {
			continue
		}
		resourceType, ok := DBNodeTypeToResourceType[data.Get("NODE_TYPE").MustString()]
		if !ok {
			continue
		}
		key := IconKey{
			NodeType: resourceType,
			SubType:  data.Get("SUB_TYPE").MustInt(),
		}
		resourceToIconID[key] = data.Get("ID").MustInt()

	}
	domainTypeToDefaultIconID := make(map[int]int)
	for _, icon := range Icons {
		for _, domainType := range IconNameToDomainType[icon.Name] {
			domainTypeToDefaultIconID[domainType] = icon.ID
		}
	}
	var domains []mysql.Domain
	err := mysql.Db.Unscoped().Find(&domains).Error
	if err != nil {
		log.Error(err)
		return domainToIconID, resourceToIconID, err
	}
	for _, domain := range domains {
		if domain.IconID != 0 {
			domainToIconID[domain.Lcuuid] = domain.IconID
		} else {
			defaultIconID, ok := domainTypeToDefaultIconID[domain.Type]
			if ok {
				domainToIconID[domain.Lcuuid] = defaultIconID
			} else {
				domainToIconID[domain.Lcuuid] = common.DEFAULT_DOMAIN_ICON
			}
		}
	}
	return domainToIconID, resourceToIconID, nil
}

// timing
func UpdateIconInfo(cfg config.ControllerConfig) (map[string]int, map[IconKey]int, error) {
	domainToIconID := make(map[string]int)
	resourceToIconID := make(map[IconKey]int)
	if !cfg.DFWebService.Enabled {
		return domainToIconID, resourceToIconID, nil
	}
	body := make(map[string]interface{})
	response, err := common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/icons", cfg.DFWebService.Host, cfg.DFWebService.Port), body)
	if err != nil {
		log.Error(err)
		return domainToIconID, resourceToIconID, err
	}
	return ParseIcon(cfg, response)
}

// subscriber
func GetIconInfo(cfg config.ControllerConfig) (map[string]int, map[IconKey]int, error) {
	domainToIconID := make(map[string]int)
	resourceToIconID := make(map[IconKey]int)
	// master region
	if cfg.TrisolarisCfg.NodeType == TrisolarisNodeTypeMaster {
		return UpdateIconInfo(cfg)
	}
	var controller mysql.Controller
	err := mysql.Db.Where("node_type = ? AND state = ?", common.CONTROLLER_NODE_TYPE_MASTER, common.CONTROLLER_STATE_NORMAL).First(&controller).Error
	if err != nil {
		log.Error(err)
		return domainToIconID, resourceToIconID, err
	}
	body := make(map[string]interface{})
	response, err := common.CURLPerform("GET", fmt.Sprintf("http://%s:%d/v1/icons/", controller.IP, cfg.ListenNodePort), body)
	if err != nil {
		log.Error(err)
		return domainToIconID, resourceToIconID, err
	}
	return ParseIcon(cfg, response)
}
