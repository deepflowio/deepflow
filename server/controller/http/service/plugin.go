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

package service

import (
	"errors"
	"fmt"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
	"gorm.io/gorm"
)

func CreatePlugin(pluginCreate *mysql.Plugin) (*model.Plugin, error) {
	var pluginFirst mysql.Plugin
	if err := mysql.Db.Where("name = ?", pluginCreate.Name).First(&pluginFirst).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, NewError(httpcommon.SERVER_ERROR,
				fmt.Sprintf("fail to query plugin by name(%s), error: %s", pluginCreate.Name, err))
		}

		if err = mysql.Db.Create(&pluginCreate).Error; err != nil {
			return nil, err
		}
		plugines, _ := GetPlugin(map[string]interface{}{"name": pluginCreate.Name})
		return &plugines[0], nil
	}

	// update by name and type
	if err := mysql.Db.Model(&mysql.Plugin{}).Where("name = ?", pluginCreate.Name).
		Updates(pluginCreate).Error; err != nil {
		return nil, err
	}

	plugins, _ := GetPlugin(map[string]interface{}{"name": pluginCreate.Name})
	return &plugins[0], nil
}

func GetPlugin(filter map[string]interface{}) ([]model.Plugin, error) {
	var plugins []mysql.Plugin
	db := mysql.Db
	if _, ok := filter["name"]; ok {
		db = db.Where("name = ?", filter["name"])
	}
	if _, ok := filter["type"]; ok {
		db = db.Where("type = ?", filter["type"])
	}
	db.Order("updated_at DESC").Find(&plugins)

	var resp []model.Plugin
	for _, plugin := range plugins {
		temp := model.Plugin{
			Name:      plugin.Name,
			Type:      plugin.Type,
			UpdatedAt: plugin.UpdatedAt.Format(common.GO_BIRTHDAY),
		}
		resp = append(resp, temp)
	}
	return resp, nil

}

func DeletePlugin(name string) error {
	var plugin model.Plugin
	if err := mysql.Db.Where("name = ?", name).First(&plugin).Error; err != nil {
		return NewError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("plugin (name: %s) not found", name))
	}

	if err := mysql.Db.Where("name = ?", name).Delete(&mysql.Plugin{}).Error; err != nil {
		return NewError(httpcommon.SERVER_ERROR, fmt.Sprintf("delete plugin (name: %s) failed, err: %v", name, err))
	}
	return nil
}
