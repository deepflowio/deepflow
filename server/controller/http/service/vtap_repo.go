/*
 * Copyright (c) 2023 Yunshan Networks
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
	. "github.com/deepflowio/deepflow/server/controller/http/service/common"
	"github.com/deepflowio/deepflow/server/controller/model"
)

const (
	IMAGE_MAX_COUNT = 20
)

func CreateVtapRepo(vtapRepoCreate *mysql.VTapRepo) (*model.VtapRepo, error) {
	var vtapRepoFirst mysql.VTapRepo
	if err := mysql.Db.Where("name = ?", vtapRepoCreate.Name).First(&vtapRepoFirst).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, NewError(common.SERVER_ERROR,
				fmt.Sprintf("fail to query vtap_repo by name(%s), error: %s", vtapRepoCreate.Name, err))
		}

		var count int64
		mysql.Db.Model(&mysql.VTapRepo{}).Count(&count)
		if count >= IMAGE_MAX_COUNT {
			return nil, fmt.Errorf("the number of image can not exceed %d", IMAGE_MAX_COUNT)
		}
		if err = mysql.Db.Create(&vtapRepoCreate).Error; err != nil {
			return nil, err
		}
		vtapRepoes, _ := GetVtapRepo(map[string]interface{}{"name": vtapRepoCreate.Name})
		return &vtapRepoes[0], nil
	}

	// update by name
	if err := mysql.Db.Model(&mysql.VTapRepo{}).Where("name = ?", vtapRepoCreate.Name).
		Updates(vtapRepoCreate).Error; err != nil {
		return nil, err
	}
	vtapRepoes, _ := GetVtapRepo(map[string]interface{}{"name": vtapRepoCreate.Name})
	return &vtapRepoes[0], nil
}

func GetVtapRepo(filter map[string]interface{}) ([]model.VtapRepo, error) {
	var vtapRepoes []mysql.VTapRepo
	db := mysql.Db
	if _, ok := filter["name"]; ok {
		db = db.Where("name = ?", filter["name"])
	}
	mysql.Db.Order("updated_at DESC").Find(&vtapRepoes)

	var resp []model.VtapRepo
	for _, vtapRepo := range vtapRepoes {
		temp := model.VtapRepo{
			Name:      vtapRepo.Name,
			Arch:      vtapRepo.Arch,
			OS:        vtapRepo.OS,
			Branch:    vtapRepo.Branch,
			RevCount:  vtapRepo.RevCount,
			CommitID:  vtapRepo.CommitID,
			UpdatedAt: vtapRepo.UpdatedAt.Format(common.GO_BIRTHDAY),
		}
		resp = append(resp, temp)
	}
	return resp, nil
}

func DeleteVtapRepo(name string) error {
	var vtapRepo mysql.VTapRepo
	if err := mysql.Db.Where("name = ?", name).First(&vtapRepo).Error; err != nil {
		return NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_repo (name: %s) not found", name))
	}

	if err := mysql.Db.Where("name = ?", name).Delete(&mysql.VTapRepo{}).Error; err != nil {
		return NewError(common.SERVER_ERROR, fmt.Sprintf("delete vtap_repo (name: %s) failed", name))
	}
	return nil
}
