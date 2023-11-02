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

package script

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"strings"

	"gorm.io/gorm"

	"github.com/bitly/go-simplejson"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

// associate sql issu 6.4.1.1
const SCRIPT_UPDATE_CLOUD_TAG = "6.4.1.1"

type ScriptVM struct {
	ID        int    `gorm:"primaryKey;autoIncrement;unique;column:id;type:int;not null"`
	CloudTags string `gorm:"column:cloud_tags;type:text"`
}

func (ScriptVM) TableName() string {
	return "vm"
}

type ScriptPodNamespace struct {
	ID        int    `gorm:"primaryKey;autoIncrement;unique;column:id;type:int;not null"`
	CloudTags string `gorm:"column:cloud_tags;type:text"`
}

func (ScriptPodNamespace) TableName() string {
	return "pod_namespace"
}

func dataStringConvertToMap(data string) map[string]string {
	result := map[string]string{}
	vSlice := strings.Split(data, ", ")
	for _, vSet := range vSlice {
		vItems := strings.Split(vSet, ":")
		if len(vItems) != 2 {
			continue
		}
		result[vItems[0]] = vItems[1]
	}
	return result
}

func ScriptUpdateCloudTags(db *gorm.DB) error {
	log.Infof("execute script (%s)", SCRIPT_UPDATE_CLOUD_TAG)
	rscResults := []map[string]interface{}{}
	err := db.Model(&mysql.DomainAdditionalResource{}).Find(&rscResults).Error
	if err != nil {
		return err
	}
	for _, resource := range rscResults {
		id, ok := resource["id"]
		if !ok {
			continue
		}
		resourceID, ok := id.(int)
		if !ok {
			continue
		}

		compressedContent, ok := resource["compressed_content"]
		if !ok {
			continue
		}
		compressedData, ok := compressedContent.(string)
		if !ok {
			continue
		}

		var b bytes.Buffer
		b.Write([]byte(compressedData))
		r, err := zlib.NewReader(&b)
		if err != nil {
			return err
		}
		defer r.Close()

		js, err := simplejson.NewFromReader(r)
		if err != nil {
			return err
		}

		var change bool
		chostCloudTags := js.Get("CHostCloudTags")
		chostCloudTagsMap := map[string]map[string]string{}
		for k, v := range chostCloudTags.MustMap() {
			vString, ok := v.(string)
			if !ok {
				continue
			}
			chostCloudTagsMap[k] = dataStringConvertToMap(vString)
		}
		if len(chostCloudTagsMap) != 0 {
			change = true
			js.Set("CHostCloudTags", chostCloudTagsMap)
		}

		nsCloudTags := js.Get("PodNamespaceCloudTags")
		nsCloudTagsMap := map[string]map[string]string{}
		for k, v := range nsCloudTags.MustMap() {
			vString, ok := v.(string)
			if !ok {
				continue
			}
			nsCloudTagsMap[k] = dataStringConvertToMap(vString)
		}
		if len(nsCloudTagsMap) != 0 {
			change = true
			js.Set("PodNamespaceCloudTags", nsCloudTagsMap)
		}

		subDomainResources := js.Get("SubDomainResources")
		for lcuuid := range subDomainResources.MustMap() {
			podNSCloudTags := subDomainResources.Get(lcuuid).Get("PodNamespaceCloudTags")
			podNSCloudTagsMap := map[string]map[string]string{}
			for k, v := range podNSCloudTags.MustMap() {
				vString, ok := v.(string)
				if !ok {
					continue
				}
				podNSCloudTagsMap[k] = dataStringConvertToMap(vString)
			}
			if len(podNSCloudTagsMap) != 0 {
				change = true
				path := []string{"SubDomainResources", lcuuid, "PodNamespaceCloudTags"}
				js.SetPath(path, podNSCloudTagsMap)
			}
		}

		if !change {
			continue
		}

		compressedByte, err := js.MarshalJSON()
		if err != nil {
			continue
		}
		db.Model(&mysql.DomainAdditionalResource{}).Where("id = ?", resourceID).Updates(mysql.DomainAdditionalResource{CompressedContent: compressedByte})
	}

	vmResults := []map[string]interface{}{}
	err = db.Model(&ScriptVM{}).Find(&vmResults).Error
	if err != nil {
		return err
	}
	for _, vm := range vmResults {
		id, ok := vm["id"]
		if !ok {
			continue
		}
		vmID, ok := id.(int)
		if !ok {
			continue
		}

		cloudTagsContent, ok := vm["cloud_tags"]
		if !ok {
			continue
		}
		// compatibility cloud_tags is Null
		if cloudTagsContent == nil {
			cloudTagsContent = ""
		}
		cloudTagsString, ok := cloudTagsContent.(string)
		if !ok {
			continue
		}
		ret := map[string]interface{}{}
		err := json.Unmarshal([]byte(cloudTagsString), &ret)
		if err == nil {
			continue
		}
		db.Unscoped().Model(&mysql.VM{}).Where("id = ?", vmID).Updates(mysql.VM{CloudTags: dataStringConvertToMap(cloudTagsString)})
	}

	nsResults := []map[string]interface{}{}
	err = db.Model(&ScriptPodNamespace{}).Find(&nsResults).Error
	if err != nil {
		return err
	}
	for _, ns := range nsResults {
		id, ok := ns["id"]
		if !ok {
			continue
		}
		nsID, ok := id.(int)
		if !ok {
			continue
		}

		cloudTagsContent, ok := ns["cloud_tags"]
		if !ok {
			continue
		}
		// compatibility cloud_tags is Null
		if cloudTagsContent == nil {
			cloudTagsContent = ""
		}
		cloudTagsString, ok := cloudTagsContent.(string)
		if !ok {
			continue
		}
		ret := map[string]interface{}{}
		err := json.Unmarshal([]byte(cloudTagsString), &ret)
		if err == nil {
			continue
		}
		db.Unscoped().Model(&mysql.PodNamespace{}).Where("id = ?", nsID).Updates(mysql.PodNamespace{CloudTags: dataStringConvertToMap(cloudTagsString)})
	}
	return nil
}
