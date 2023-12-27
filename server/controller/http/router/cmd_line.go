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

package router

import (
	"bytes"
	"fmt"
	"github.com/gin-gonic/gin"
	//"github.com/gin-gonic/gin/binding"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	. "github.com/deepflowio/deepflow/server/controller/http/router/common"
	"github.com/golang/protobuf/proto"
)

type CmdLine struct{}

func NewCmdLine() *CmdLine {
	return new(CmdLine)
}

func (c *CmdLine) RegisterTo(e *gin.Engine) {
	e.POST("/v1/cmd/", createCmdLine)
}

var schedulingCfg = `
buffers {
    size_kb: 522240
    fill_policy: RING_BUFFER
}

data_sources {
  config {
    name: "linux.ftrace"
    target_buffer: 0
    ftrace_config {
        enable_function_graph: true
        symbolize_ksyms: true
      ftrace_events: "sched_switch"
      ftrace_events: "sched_waking"
      ftrace_events: "sched_wakeup_new"

      ftrace_events: "task_newtask"
      ftrace_events: "task_rename"

      ftrace_events: "sched_process_exec"
      ftrace_events: "sched_process_exit"
      ftrace_events: "sched_process_fork"
      ftrace_events: "sched_process_free"
      ftrace_events: "sched_process_hang"
      ftrace_events: "sched_process_wait"
    }
  }
}

data_sources {
  config {
    name: "linux.process_stats"
    target_buffer: 0
  }

}

duration_ms: %d`

var traceboxCommand1 = trident.Command{
	Name:      proto.String("echo"),
	Arguments: []string{},
}
var traceboxCommand2 = trident.Command{
	Name:      proto.String("tracebox"),
	Arguments: []string{"-o", "-", "-c", "-", "--txt"},
}

var offCpuCommand1 = trident.Command{
	Name:      proto.String("offcputime-bpfcc"),
	Arguments: []string{"-df", "30"},
}

var offCpuCommand2 = trident.Command{
	Name:      proto.String("perl"),
	Arguments: []string{"/root/FlameGraph/flamegraph.pl", "--title=\"Off-CPU graph\""},
}

func createCmdLine(c *gin.Context) {
	var vtap mysql.VTap
	profileType, ok := c.GetPostForm("profile_type")
	if !ok {
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "can not not get form data(profile_type)")
		return
	}
	vtapName, ok := c.GetPostForm("vtap_name")
	if !ok {
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "can not not get form data(vtap_name)")
		return
	}
	durationStr, ok := c.GetPostForm("duration")
	if !ok {
		BadRequestResponse(c, httpcommon.INVALID_PARAMETERS, "can not not get form data(duration)")
		return
	}
	schedulingCfgR, _ := c.GetPostForm("schedulingCfg")
	duration, _ := strconv.Atoi(durationStr)
	log.Infof("CMD profile_type=%s, vtap_name=%s, duration=%d", profileType, vtapName, duration)
	db := mysql.Db
	err := db.Where("name = ?", vtapName).First(&vtap).Error
	if err != nil {
		BadRequestResponse(c, httpcommon.SERVER_ERROR, err.Error())
		return
	}

	key := vtap.CtrlIP + "-" + vtap.CtrlMac
	fileName := ""
	exData := new(ExchangeData)
	if profileType == "perfetto-tracebox" {
		fileName = "perfetto-tracebox.log"
		schedulingCfgTmp := fmt.Sprintf(schedulingCfg, duration*1000)
		if len(schedulingCfgR) > 0 {
			var buffer bytes.Buffer
			buffer.WriteString(schedulingCfgR)
			buffer.WriteString(fmt.Sprintf("\nduration_ms: %d", duration*1000))
			schedulingCfgTmp = buffer.String()
			log.Infof("CMD schedulingCfg = %s", schedulingCfgTmp)
		}
		log.Infof("CMD %s", schedulingCfg)
		log.Infof("CMD schedulingCfg = %s", schedulingCfgTmp)
		log.Infof("CMD len %d", len(schedulingCfgTmp))
		traceboxCommand1.Arguments = []string{schedulingCfgTmp}
		exData.commandRequet = &trident.CommandRequest{
			Pipeline: []*trident.Command{&traceboxCommand1, &traceboxCommand2},
		}
	} else if profileType == "perf-off-cpu" {
		offCpuCommand1Tmp := proto.Clone(&offCpuCommand1).(*trident.Command)
		offCpuCommand1Tmp.Arguments[1] = durationStr
		exData.commandRequet = &trident.CommandRequest{
			Pipeline: []*trident.Command{offCpuCommand1Tmp, &offCpuCommand2},
		}
		fileName = "perf-off-cpu.svg"
	}

	log.Infof("send request data to agent(%s)", key)
	cmdManager.setCmdRequest(key, exData)
	time.Sleep(time.Duration(duration) * time.Second)
	count := 20
	for {
		exData := cmdManager.getResponseData(key)
		if exData != nil {
			log.Info("CMD get response data from vtap completly")
			c.Writer.Header().Add("Content-type", "application/octet-stream")
			c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=utf-8''%s", fileName))
			_, err = io.Copy(c.Writer, exData.GetResponseData())
			break
		}
		time.Sleep(3 * time.Second)
		count--
		if count == 0 {
			log.Infof("CMD get response data from agent(%s) timeout", key)
			break
		}
	}
	DeleteData(key)
}

type ExchangeData struct {
	commandRequet *trident.CommandRequest
	responseData  *bytes.Buffer
}

func NewExchangeData() *ExchangeData {
	return &ExchangeData{
		commandRequet: &trident.CommandRequest{},
	}
}

func (e *ExchangeData) SetResponseData(data *bytes.Buffer) {
	e.responseData = data
}

func (e *ExchangeData) GetResponseData() *bytes.Buffer {
	return e.responseData
}

func (e *ExchangeData) GetCommandRequest() *trident.CommandRequest {
	return e.commandRequet
}

var cmdManager *CmdManager = NewCmdManager()

type CmdManager struct {
	cmdM            sync.RWMutex
	vtapCmdMap      map[string]*ExchangeData
	responseM       sync.RWMutex
	vtapResponseMap map[string]*ExchangeData

	reqM   sync.Mutex
	reqMap map[string]bool
}

func (c *CmdManager) getReqIF(key string) bool {
	c.reqM.Lock()
	reqIF := c.reqMap[key]
	c.reqM.Unlock()
	return reqIF
}

func (c *CmdManager) setReqIF(key string, data bool) {
	c.reqM.Lock()
	c.reqMap[key] = data
	c.reqM.Unlock()
}

func NewCmdManager() *CmdManager {
	return &CmdManager{
		vtapCmdMap:      make(map[string]*ExchangeData),
		vtapResponseMap: make(map[string]*ExchangeData),
	}
}

func DeleteData(key string) {
	cmdManager.setCmdRequest(key, nil)
	cmdManager.setResponseData(key, nil)
}

func GetCmdRequest(key string) *ExchangeData {
	return cmdManager.getCmdRequest(key)
}

func SetCmdRequest(key string, data *ExchangeData) {
	cmdManager.setCmdRequest(key, data)
}

func SetResponseData(key string, data *ExchangeData) {
	cmdManager.setResponseData(key, data)
}

func GetResponseData(key string) *ExchangeData {
	return cmdManager.getResponseData(key)
}

func (m *CmdManager) getCmdRequest(key string) *ExchangeData {
	m.cmdM.RLock()
	cmdRequest := m.vtapCmdMap[key]
	if cmdRequest != nil {
		m.vtapCmdMap[key] = nil
	}
	m.cmdM.RUnlock()

	return cmdRequest
}

func (m *CmdManager) setCmdRequest(key string, data *ExchangeData) {
	m.cmdM.Lock()
	m.vtapCmdMap[key] = data
	m.cmdM.Unlock()
}

func (m *CmdManager) setResponseData(key string, data *ExchangeData) {
	m.responseM.Lock()
	m.vtapResponseMap[key] = data
	m.responseM.Unlock()
}

func (m *CmdManager) getResponseData(key string) *ExchangeData {
	m.responseM.Lock()
	res := m.vtapResponseMap[key]
	if res != nil {
		m.vtapResponseMap[key] = nil
	}
	m.responseM.Unlock()

	return res
}
