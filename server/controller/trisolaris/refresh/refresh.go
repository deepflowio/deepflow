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

package refresh

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	"github.com/deepflowys/deepflow/server/controller/common"
	models "github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/trisolaris/dbmgr"
)

var log = logging.MustGetLogger("trisolaris/refresh")

type RefreshOP struct {
	db         *gorm.DB
	nodeIP     string
	refreshIPs []string
}

var refreshOP *RefreshOP = nil

func NewRefreshOP(db *gorm.DB, nodeIP string) *RefreshOP {
	refreshOP = &RefreshOP{
		nodeIP: nodeIP,
		db:     db,
	}

	return refreshOP
}

func isTCPActive(ip string, port string) error {
	conn, err := net.DialTimeout("tcp", ip+":"+port, 2*time.Second)
	if err != nil {
		return err
	} else {
		if conn != nil {
			conn.Close()
		} else {
			return fmt.Errorf("check tcp alive failed (ip:%s, port:%s)", ip, port)
		}
	}

	return nil
}

var urlFormat = "http://%s:%s/v1/caches/?"

func RefreshCache(dataTypes []string) {
	if refreshOP != nil {
		go refreshOP.refreshCache(dataTypes)
	}
}

func (r *RefreshOP) refreshCache(dataTypes []string) {
	controllerIPs := r.refreshIPs
	if len(dataTypes) == 0 || len(controllerIPs) == 0 {
		return
	}
	log.Infof("refresh cache for trisolaris(%v)", controllerIPs)
	params := url.Values{}
	for _, dataType := range dataTypes {
		params.Add("type", dataType)
	}
	for _, controllerIP := range controllerIPs {
		err := isTCPActive(controllerIP, common.CONTROLLER_HTTP_PORT)
		if err != nil {
			log.Errorf("%s:%s unreachable, err(%s)", controllerIP, common.CONTROLLER_HTTP_PORT, err)
			continue
		}
		trisolaris_url := fmt.Sprintf(urlFormat, controllerIP, common.CONTROLLER_HTTP_PORT) + params.Encode()
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

	refreshIPs := make([]string, 0, len(dbControllers))
	for _, controller := range dbControllers {
		region, ok := controllerIPToRegion[controller.IP]
		if ok && localRegion == region {
			refreshIPs = append(refreshIPs, controller.PodIP)
		} else {
			refreshIPs = append(refreshIPs, controller.IP)
		}
	}
	r.refreshIPs = refreshIPs
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
