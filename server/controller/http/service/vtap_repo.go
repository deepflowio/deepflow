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
	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/refresh"
)

const (
	IMAGE_MAX_COUNT = 20
)

func CreateVtapRepo(orgID int, vtapRepoCreate *mysqlmodel.VTapRepo) (*model.VtapRepo, error) {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	var vtapRepoFirst mysqlmodel.VTapRepo
	if err := db.Where("name = ?", vtapRepoCreate.Name).First(&vtapRepoFirst).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, response.ServiceError(httpcommon.SERVER_ERROR,
				fmt.Sprintf("fail to query vtap_repo by name(%s), error: %s", vtapRepoCreate.Name, err))
		}

		var count int64
		db.Model(&mysqlmodel.VTapRepo{}).Count(&count)
		if count >= IMAGE_MAX_COUNT {
			return nil, fmt.Errorf("the number of image can not exceed %d", IMAGE_MAX_COUNT)
		}
		if err = db.Create(&vtapRepoCreate).Error; err != nil {
			return nil, err
		}
		vtapRepoes, _ := GetVtapRepo(orgID, map[string]interface{}{"name": vtapRepoCreate.Name})
		return &vtapRepoes[0], nil
	}

	// update by name
	if err := db.Model(&mysqlmodel.VTapRepo{}).Where("name = ?", vtapRepoCreate.Name).
		Updates(vtapRepoCreate).Error; err != nil {
		return nil, err
	}

	// refresh all server delete image cache
	refresh.RefreshCache(orgID, []common.DataChanged{common.DATA_CHANGED_IMAGE}, vtapRepoCreate.Name)

	vtapRepoes, _ := GetVtapRepo(orgID, map[string]interface{}{"name": vtapRepoCreate.Name})
	return &vtapRepoes[0], nil
}

func GetVtapRepo(orgID int, filter map[string]interface{}) ([]model.VtapRepo, error) {
	var vtapRepoes []mysqlmodel.VTapRepo
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return nil, err
	}
	db := dbInfo.DB
	if _, ok := filter["name"]; ok {
		db = db.Where("name = ?", filter["name"])
	}
	fieldsExculdImage := []string{"id", "name", "arch", "os", "branch", "rev_count", "commit_id", "created_at", "updated_at", "k8s_image"}
	db.Order("updated_at DESC").Select(fieldsExculdImage).Find(&vtapRepoes)

	var resp []model.VtapRepo
	for _, vtapRepo := range vtapRepoes {
		temp := model.VtapRepo{
			Name:      vtapRepo.Name,
			Arch:      vtapRepo.Arch,
			OS:        vtapRepo.OS,
			Branch:    vtapRepo.Branch,
			RevCount:  vtapRepo.RevCount,
			CommitID:  vtapRepo.CommitID,
			K8sImage:  vtapRepo.K8sImage,
			UpdatedAt: vtapRepo.UpdatedAt.Format(common.GO_BIRTHDAY),
		}
		resp = append(resp, temp)
	}
	return resp, nil
}

func DeleteVtapRepo(orgID int, name string) error {
	dbInfo, err := mysql.GetDB(orgID)
	if err != nil {
		return err
	}
	db := dbInfo.DB
	var vtapRepo mysqlmodel.VTapRepo
	if err := db.Where("name = ?", name).Select("name", "id").First(&vtapRepo).Error; err != nil {
		return response.ServiceError(httpcommon.RESOURCE_NOT_FOUND, fmt.Sprintf("vtap_repo (name: %s) not found", name))
	}

	if err := db.Where("name = ?", name).Delete(&mysqlmodel.VTapRepo{}).Error; err != nil {
		return response.ServiceError(httpcommon.SERVER_ERROR, fmt.Sprintf("delete vtap_repo (name: %s) failed", name))
	}
	return nil
}
