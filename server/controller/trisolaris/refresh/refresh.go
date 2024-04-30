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

package refresh

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/common"
	models "github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/trisolaris/dbmgr"
)

var log = logging.MustGetLogger("trisolaris/refresh")

type RefreshOP struct {
	db               *gorm.DB
	nodeIP           string
	localRefreshIPs  []string
	remoteRefreshIPs []string
}

var refreshOP *RefreshOP = nil

func NewRefreshOP(db *gorm.DB, nodeIP string) *RefreshOP {
	refreshOP = &RefreshOP{
		nodeIP: nodeIP,
		db:     db,
	}

	return refreshOP
}

var urlFormat = "http://%s:%d/v1/caches/?"

// orgid equal to 0 means refreshing all organization data
func RefreshCache(orgID int, dataTypes []common.DataChanged) {
	if refreshOP != nil {
		go refreshOP.refreshCache(orgID, dataTypes)
	}
}

func (r *RefreshOP) refreshCache(orgID int, dataTypes []common.DataChanged) {
	localControllerIPs := r.localRefreshIPs
	remoteControllerIPs := r.remoteRefreshIPs
	if len(dataTypes) == 0 || (len(localControllerIPs) == 0 && len(remoteControllerIPs) == 0) {
		return
	}
	log.Infof("refresh cache for trisolaris(%v %v)", localControllerIPs, remoteControllerIPs)
	params := url.Values{}
	params.Add("org_id", strconv.Itoa(orgID))
	for _, dataType := range dataTypes {
		params.Add("type", string(dataType))
	}
	paramsEncode := params.Encode()
	for _, controllerIP := range localControllerIPs {
		err := common.IsTCPActive(controllerIP, common.GConfig.HTTPPort)
		if err != nil {
			log.Errorf("%s:%d unreachable, err(%s)", controllerIP, common.GConfig.HTTPPort, err)
			continue
		}
		trisolaris_url := fmt.Sprintf(urlFormat, controllerIP, common.GConfig.HTTPPort) + paramsEncode
		resp, err := common.CURLPerform("PUT", trisolaris_url, nil)
		if err != nil {
			log.Errorf("request trisolaris failed: %s, URL: %s", resp, trisolaris_url)
		}
	}
	for _, controllerIP := range remoteControllerIPs {
		err := common.IsTCPActive(controllerIP, common.GConfig.HTTPNodePort)
		if err != nil {
			log.Errorf("%s:%d unreachable, err(%s)", controllerIP, common.GConfig.HTTPNodePort, err)
			continue
		}
		trisolaris_url := fmt.Sprintf(urlFormat, controllerIP, common.GConfig.HTTPNodePort) + paramsEncode
		resp, err := common.CURLPerform("PUT", trisolaris_url, nil)
		if err != nil {
			log.Errorf("request trisolaris failed: %s, URL: %s", resp, trisolaris_url)
		}
	}
}

func (r *RefreshOP) generateRefreshIPs() {
	dbControllers, err := dbmgr.DBMgr[models.Controller](r.db).Gets()
	if err != nil {
		log.Error(err)
		return
	}
	if len(dbControllers) == 0 {
		return
	}

	controllerIPToRegion := make(map[string]string)
	var localRegion string
	azCons, _ := dbmgr.DBMgr[models.AZControllerConnection](r.db).Gets()
	for _, azCon := range azCons {
		if azCon.ControllerIP == r.nodeIP {
			localRegion = azCon.Region
		}
		controllerIPToRegion[azCon.ControllerIP] = azCon.Region
	}

	localRefreshIPs := make([]string, 0, len(dbControllers))
	remoteRefreshIPs := make([]string, 0, len(dbControllers))
	for _, controller := range dbControllers {
		region, ok := controllerIPToRegion[controller.IP]
		if ok && localRegion == region {
			localRefreshIPs = append(localRefreshIPs, controller.PodIP)
		} else {
			remoteRefreshIPs = append(remoteRefreshIPs, controller.IP)
		}
	}
	r.localRefreshIPs = localRefreshIPs
	r.remoteRefreshIPs = remoteRefreshIPs
}

func (r *RefreshOP) TimedRefreshIPs() {
	r.generateRefreshIPs()
	ticker := time.NewTicker(time.Minute).C
	for {
		select {
		case <-ticker:
			log.Info("start generate refresh IPs from timed")
			r.generateRefreshIPs()
			log.Info("end generate refresh IPs from timed")
		}
	}
}
