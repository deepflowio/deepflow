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

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/model"
)

func CreatePlugin(db *mysql.DB, pluginCreate *mysqlmodel.Plugin) (*model.Plugin, error) {
	var pluginFirst mysqlmodel.Plugin
	if err := db.Where("name = ?", pluginCreate.Name).First(&pluginFirst).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, response.ServiceError(httpcommon.SERVER_ERROR,
				fmt.Sprintf("fail to query plugin by name(%s), error: %s", pluginCreate.Name, err))
		}

		if err = db.Create(&pluginCreate).Error; err != nil {
			return nil, err
		}
		plugines, _ := GetPlugin(db, map[string]interface{}{"name": pluginCreate.Name})
		return &plugines[0], nil
	}

	// update by name and type
	if err := db.Model(&mysqlmodel.Plugin{}).Where("name = ?", pluginCreate.Name).
		Updates(pluginCreate).Error; err != nil {
		return nil, err
	}

	plugins, _ := GetPlugin(db, map[string]interface{}{"name": pluginCreate.Name})
	return &plugins[0], nil
}

func GetPlugin(db *mysql.DB, filter map[string]interface{}) ([]model.Plugin, error) {
	var plugins []mysqlmodel.Plugin
	queryDB := db.DB
	if _, ok := filter["name"]; ok {
		queryDB = queryDB.Where("name = ?", filter["name"])
	}
	if _, ok := filter["type"]; ok {
		queryDB = queryDB.Where("type = ?", filter["type"])
	}
	queryDB.Order("updated_at DESC").Find(&plugins)

	var resp []model.Plugin
	for _, plugin := range plugins {
		temp := model.Plugin{
			Name:      plugin.Name,
			Type:      plugin.Type,
			UpdatedAt: plugin.UpdatedAt.Format(common.GO_BIRTHDAY),
			User:      plugin.User,
		}
		resp = append(resp, temp)
	}
	return resp, nil

}

func DeletePlugin(db *mysql.DB, name string) error {
	var plugin model.Plugin
	if err := db.Where("name = ?", name).First(&plugin).Error; err != nil {
		return response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("plugin (name: %s) not found", name))
	}

	if err := db.Where("name = ?", name).Delete(&mysqlmodel.Plugin{}).Error; err != nil {
		return response.ServiceError(httpcommon.SERVER_ERROR, fmt.Sprintf("delete plugin (name: %s) failed, err: %v", name, err))
	}
	return nil
}
