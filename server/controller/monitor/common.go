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

package monitor

import (
	"fmt"
	"net/http"
	"time"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("monitor")

type dfHostCheck struct {
	lastTimeUnix int64
}

func newDFHostCheck() *dfHostCheck {
	return &dfHostCheck{lastTimeUnix: time.Now().Unix()}
}

func (h *dfHostCheck) duration() int64 {
	return (time.Now().Unix() - h.lastTimeUnix)
}

// TODO: 后续修改为通过RPC调用
func isActive(urlPrefix string, ip string, port int) bool {
	url := fmt.Sprintf(urlPrefix, ip, port)
	client := http.Client{
		Timeout: 60 * time.Second,
	}
	response, err := client.Get(url)
	if err != nil {
		log.Warningf("curl (%s) failed, (%v)", url, err)
	} else if response.StatusCode != http.StatusOK {
		log.Warning("curl (%s) failed, (%d)", url, response.StatusCode)
	}
	if response != nil && response.Body != nil {
		response.Body.Close()
	}
	return err == nil && response.StatusCode == http.StatusOK
}

func getIPMap(hostType string) (map[string]bool, error) {
	var res map[string]bool
	switch hostType {
	case common.HOST_TYPE_CONTROLLER:
		var controllers []mysql.Controller
		mysql.Db.Where("state = ?", common.HOST_STATE_COMPLETE).Find(&controllers)
		res = make(map[string]bool, len(controllers))
		for _, controller := range controllers {
			res[controller.IP] = true
		}
	case common.HOST_TYPE_ANALYZER:
		var analyzers []mysql.Analyzer
		mysql.Db.Where("state = ?", common.HOST_STATE_COMPLETE).Find(&analyzers)
		res = make(map[string]bool, len(analyzers))
		for _, analyzer := range analyzers {
			res[analyzer.IP] = true
		}
	default:
		return nil, fmt.Errorf("does not support type: %s", hostType)
	}
	return res, nil
}
