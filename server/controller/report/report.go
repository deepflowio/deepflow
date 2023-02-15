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

package report

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/op/go-logging"
	"gorm.io/gorm"

	. "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var log = logging.MustGetLogger("report")

type ReportServer struct {
	db *gorm.DB
	ReportData
}

var serverBranch, serverRevCount, serverCommitID string

func SetServerInfo(branch string, revCount string, commitID string) {
	serverBranch = branch
	serverRevCount = revCount
	serverCommitID = commitID
}

func NewReportServer(db *gorm.DB) *ReportServer {
	return &ReportServer{
		db: db,
		ReportData: ReportData{
			ServerBranch:   serverBranch,
			ServerRevCount: serverRevCount,
			ServerCommitID: serverCommitID,
		},
	}
}

type ReportData struct {
	DFUUID         string      `json:"deepflowDeploymentUUID"`
	ServerRevCount string      `json:"serverRevCount"`
	ServerCommitID string      `json:"serverCommitId"`
	ServerBranch   string      `json:"serverBranch"`
	ReportTime     string      `json:"reportTime"`
	ServerReplicas int64       `json:"serverReplicas"`
	Agents         []AgentData `json:"agents"`
}

type AgentData struct {
	Type     string `json:"type"`
	RevCount string `json:"revCount"`
	CommitID string `json:"commitId"`
	Branch   string `json:"branch"`
	Count    int    `json:"count"`
}

type AgentDataKey struct {
	Type    int
	Version string
}

func getRandom(min int, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

const minutesPerHour = 60

func (r *ReportServer) StartReporting() {
	timeAfter := time.After(time.Duration(getRandom(1*minutesPerHour, 2*minutesPerHour)) * time.Minute)
	select {
	case <-timeAfter:
		r.report()
	}
	ticker := time.NewTicker(time.Duration(getRandom(12*minutesPerHour, 36*minutesPerHour)) * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.report()
			ticker = time.NewTicker(time.Duration(getRandom(12*minutesPerHour, 36*minutesPerHour)) * time.Minute)
		}
	}
}

func (r *ReportServer) report() {
	log.Info("start reporting")
	if r.DFUUID == "" {
		r.DFUUID = GetCAMD5()
	}
	var controllerCount int64
	var vtaps []mysql.VTap
	r.db.Model(&mysql.Controller{}).Count(&controllerCount)
	r.db.Find(&vtaps)
	agentDataMap := make(map[AgentDataKey]int)
	for _, vtap := range vtaps {
		agentDataKey := AgentDataKey{
			Type:    vtap.Type,
			Version: vtap.Revision,
		}
		agentDataMap[agentDataKey] = agentDataMap[agentDataKey] + 1
	}
	agentData := make([]AgentData, 0, len(agentDataMap))
	for key, value := range agentDataMap {
		var revCount, commitID, branch string
		splitStr := strings.Split(key.Version, " ")
		if len(splitStr) == 2 {
			branch = splitStr[0]
			splitStr = strings.Split(splitStr[1], "-")
			if len(splitStr) == 2 {
				revCount = splitStr[0]
				commitID = splitStr[1]
			}
		} else {
			splitStr = strings.Split(key.Version, "-")
			if len(splitStr) == 2 {
				revCount = splitStr[0]
				commitID = splitStr[1]
			}
		}
		agentData = append(agentData,
			AgentData{
				Type:     VTapTypeName[key.Type],
				RevCount: revCount,
				CommitID: commitID,
				Branch:   branch,
				Count:    value,
			})
	}
	r.Agents = agentData
	r.ServerReplicas = controllerCount
	r.ReportTime = time.Now().Format(GO_BIRTHDAY)
	go r.send()
}

var URL = "https://usage.deepflow.yunshan.net/api/v1/report"

func (r *ReportServer) send() {
	bodyStr, err := json.Marshal(r.ReportData)
	if err != nil {
		log.Error(err)
		return
	}
	log.Info(string(bodyStr))
	req, err := http.NewRequest("POST", URL, bytes.NewReader(bodyStr))
	if err != nil {
		log.Error(err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain")
	client := &http.Client{Timeout: time.Second * 30}
	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		log.Error(err, res)
	}
}
