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

package huawei

import (
	"fmt"
	"time"

	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

// This project is not an actual project that is visible to the console, so ignore its exceptions when learning
var ignoredProjectName = "MOS"

type Token struct {
	token     string
	expiresAt string
}

// 华为云中用于请求token的凭证
type Project struct {
	name string
	id   string
}

// 检查token是否过期
// 记录的expire与当前时间比较，离失效时间大于5m，则返回false，否则返回true
func (t *Token) isExpired() bool {
	expire, err := time.Parse(time.RFC3339, t.expiresAt)
	if err != nil {
		log.Errorf("parse expire time error: %s, %v", expire, err)
		return false
	}
	if time.Now().UTC().Sub(expire).Minutes() > 5 {
		return true
	}
	return false
}

func (h *HuaWei) getToken(projectName, projectID string) (*Token, error) {
	t, ok := h.projectTokenMap[Project{projectName, projectID}]
	if !ok || t.isExpired() {
		t, err := h.createToken(projectName, projectID)
		if err != nil {
			return t, err
		}
		return t, err
	}
	return t, nil
}

func (h *HuaWei) createToken(projectName, projectID string) (*Token, error) {
	authBody := map[string]interface{}{
		"auth": map[string]interface{}{
			"identity": map[string]interface{}{
				"methods": []string{"password"},
				"password": map[string]interface{}{
					"user": map[string]interface{}{
						"domain": map[string]interface{}{
							"name": h.config.AccountName,
						},
						"name":     h.config.IAMName,
						"password": h.config.Password,
					},
				},
			},
			"scope": map[string]interface{}{
				"project": map[string]interface{}{
					"id": projectID,
				},
			},
		},
	}
	resp, err := RequestPost(
		fmt.Sprintf("https://%s.%s.%s/v3/auth/tokens", h.config.IAMHostPrefix, projectName, h.config.Domain), time.Duration(h.httpTimeout), authBody,
	)
	if err != nil {
		return nil, err
	}
	return &Token{resp.Get("X-Subject-Token").MustString(), resp.Get("token").Get("expires_at").MustString()}, nil
}

func (h *HuaWei) refreshTokenMap() error {
	log.Infof("refresh cloud (%s) token map", h.name, logger.NewORGPrefix(h.orgID))
	var err error
	token, err := h.getToken(h.config.ProjectName, h.config.ProjectID)
	if err != nil {
		return err
	}
	h.toolDataSet.configProjectToken = token.token

	projectIDs := []string{}
	jProjects, err := h.getRawData(newRawDataGetContext(fmt.Sprintf("https://%s/v3/auth/projects", h.config.IAMHost), token.token, "projects", pageQueryMethodNotPage))
	if err != nil {
		return err
	}
	for i := range jProjects {
		jp := jProjects[i]
		if !cloudcommon.CheckJsonAttributes(jp, []string{"id", "name"}) {
			err := fmt.Errorf("json attributes not match, id: %s, name: %s", jp.Get("id").MustString(), jp.Get("name").MustString())
			log.Error(err.Error(), logger.NewORGPrefix(h.orgID))
			return err
		}
		name := jp.Get("name").MustString()
		if _, ok := h.config.IncludeRegions[name]; !ok {
			log.Infof("exclude project: %s, not included", name, logger.NewORGPrefix(h.orgID))
			continue
		}

		id := jp.Get("id").MustString()
		token, err = h.getToken(name, id)
		if err != nil {
			msg := fmt.Sprintf("get token failed, pass this project (%s, %s)", name, id)
			if name == ignoredProjectName {
				log.Info(msg, logger.NewORGPrefix(h.orgID))
			} else {
				log.Error(msg, logger.NewORGPrefix(h.orgID))
			}
			return err
		}
		projectIDs = append(projectIDs, id)
		h.projectTokenMap[Project{name, id}] = token
	}

	for p, t := range h.projectTokenMap {
		if !common.Contains(projectIDs, p.id) {
			log.Infof("exclude project: %+v, not in project list: %+v", p, jProjects, logger.NewORGPrefix(h.orgID))
			delete(h.projectTokenMap, p)
			continue
		}
		jvpcs, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://vpc.%s.%s/v1/%s/vpcs", p.name, h.config.Domain, p.id), t.token, "vpcs", pageQueryMethodMarker,
		))
		if err != nil {
			return err
		} else if len(jvpcs) == 0 {
			log.Infof("exclude project: %+v, has no vpc", p, logger.NewORGPrefix(h.orgID))
			delete(h.projectTokenMap, p)
			continue
		}
		log.Infof("project info (%+v)", p, logger.NewORGPrefix(h.orgID))
		log.Debugf("token info (%+v)", t, logger.NewORGPrefix(h.orgID))
	}
	return nil
}
