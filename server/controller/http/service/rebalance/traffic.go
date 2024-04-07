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

package rebalance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/model"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/querier/config"
)

var log = logging.MustGetLogger("service.rebalance")

func (r *AnalyzerInfo) RebalanceAnalyzerByTraffic(ifCheckout bool, dataDuration int) (*model.VTapRebalanceResult, error) {
	if r.dbInfo == nil {
		r.dbInfo = &DBInfo{}
		err := r.dbInfo.Get()
		if err != nil {
			return nil, err
		}
	}
	info := r.dbInfo

	regionToAZLcuuids := make(map[string][]string)
	azToRegion := make(map[string]string, len(info.AZs))
	for _, az := range info.AZs {
		regionToAZLcuuids[az.Region] = append(regionToAZLcuuids[az.Region], az.Lcuuid)
		azToRegion[az.Lcuuid] = az.Region
	}
	azToVTaps := make(map[string][]*mysql.VTap)
	for i, vtap := range info.VTaps {
		azToVTaps[vtap.AZ] = append(azToVTaps[vtap.AZ], &info.VTaps[i])
	}
	ipToAnalyzer := make(map[string]*mysql.Analyzer)
	for i, analyzer := range info.Analyzers {
		ipToAnalyzer[analyzer.IP] = &info.Analyzers[i]
	}
	azToAnalyzers := GetAZToAnalyzers(info.AZAnalyzerConns, regionToAZLcuuids, ipToAnalyzer)

	if r.regionToVTapNameToTraffic == nil {
		regionToVTapNameToTraffic, err := r.getVTapTraffic(dataDuration, regionToAZLcuuids)
		if err != nil {
			return nil, fmt.Errorf("get traffic data failed: %v", err)
		}
		b, _ := json.Marshal(regionToVTapNameToTraffic)
		log.Infof("region to vtap name to traffic: %v", string(b))
		r.regionToVTapNameToTraffic = regionToVTapNameToTraffic
	}

	response := &model.VTapRebalanceResult{}
	for _, az := range info.AZs {
		azVTaps, ok := azToVTaps[az.Lcuuid]
		if !ok {
			continue
		}
		azAnalyzers, ok := azToAnalyzers[az.Lcuuid]
		if !ok {
			continue
		}
		vtapNameToID := make(map[string]int, len(azVTaps))
		vTapIDToVTap := make(map[int]*mysql.VTap, len(azVTaps))
		vTapIDToTraffic := make(map[int]int64)
		for _, vtap := range azVTaps {
			vtapNameToID[vtap.Name] = vtap.ID
			vTapIDToTraffic[vtap.ID] = 0
			vTapIDToVTap[vtap.ID] = vtap
		}
		for vtapName, traffic := range r.regionToVTapNameToTraffic[az.Region] {
			vtapID, ok := vtapNameToID[vtapName]
			if !ok {
				continue
			}
			vTapIDToTraffic[vtapID] = traffic
		}
		if len(vTapIDToTraffic) == 0 {
			log.Warningf("no vtaps to balance, region(%s)", az.Region)
			continue
		}
		p := &AZInfo{
			lcuuid:          az.Lcuuid,
			vTapIDToTraffic: vTapIDToTraffic,
			vtaps:           azVTaps,
			analyzers:       azAnalyzers,
		}
		vTapIDToChangeInfo, azVTapRebalanceResult := p.rebalanceAnalyzer(ifCheckout)
		if azVTapRebalanceResult != nil {
			response.TotalSwitchVTapNum += azVTapRebalanceResult.TotalSwitchVTapNum
			response.Details = append(response.Details, azVTapRebalanceResult.Details...)
		}
		if azVTapRebalanceResult != nil && azVTapRebalanceResult.TotalSwitchVTapNum != 0 {
			for vtapID, changeInfo := range vTapIDToChangeInfo {
				if changeInfo.OldIP != changeInfo.NewIP {
					log.Infof("az(%s) vtap(%v) analyzer ip changed: %s -> %s", az.Lcuuid, vtapID, changeInfo.OldIP, changeInfo.NewIP)
				}
			}
		}

		// update counter
		updateCounter(vTapIDToVTap, vtapNameToID, vTapIDToChangeInfo)
	}
	if response.TotalSwitchVTapNum != 0 {
		log.Infof("vtap rebalance result switch_total_num(%v)", response.TotalSwitchVTapNum)
		for _, detail := range response.Details {
			log.Infof("vtap rebalance result az(%v) ip(%v) state(%v) before_vtap_num(%v) after_vtap_num(%v), switch_vtap_num(%v) before_vtap_weight(%v) after_vtap_weight(%v)",
				detail.AZ, detail.IP, detail.State, detail.BeforeVTapNum, detail.AfterVTapNum, detail.SwitchVTapNum, detail.BeforeVTapWeights, detail.AfterVTapWeights)
		}
	}

	return response, nil
}

type AZInfo struct {
	lcuuid          string
	vTapIDToTraffic map[int]int64
	vtaps           []*mysql.VTap
	analyzers       []*mysql.Analyzer
}

type ChangeInfo struct {
	OldIP     string
	NewIP     string
	NewWeight float64
}

// rebalanceAnalyzer balances vtaps on the analyzer in an az
// 1. calculate the total traffic data sent by vtaps
//   - beforeTraffic is used to record the total traffic before rebalance and calculate before weight
//   - afterTraffic is used to record the total traffic after rebalance and calculate after weight, contains newly added vtap
//     (traffic is 0, virtual traffic is allocated, virtual traffic = sum of traffic of allocated vtap / number of allocated vtap)
//   - add the newly added vtap to the queue to be reallocated
//
// 2. based on the total traffic, calculate the average amount of data received on each analyzer: avg = afterTraffic / total number of normal agents
// 3. range vtaps assigned analyzer
//   - update the total traffic on the analyzer: cur = cur + vtap_traffic
//
// 4. range analyzers
//   - analyzer exception: add all vtaps on the exception analyzer to the queue to be reallocated
//   - analyzer normal
//     range vtaps on the analyzer
//     cur <= avg, continue
//     cur > avg, if agent_num = 1, remain unchanged, if agent_num > 1, add the vtap with the smallest traffic to the queue to be reallocated, and re-traverse the vtap until the conditions are not met
//
// 5. the vtap queues to be reallocated are arranged from large to small traffic volume, and range the queues
//   - range the analyzers and select the analyzer with the smallest traffic to assign to vtap
//   - until the allocation ends
//
// 6. update analyzer weights
//   - vtap weight = traffic sent by vtap / traffic sent by all vtap
//   - average weight of analyzer = sum of vtap weights / number of normal analyzers
//   - analyzer weight = sum of vtap weights on anlyzer / average weight of analyzer
//
// rebalanceAnalyzer 函数用于平衡一个可用区中数据节点上的 vtaps
// 1、计算采集器发送的总流量 traffic
//   - beforeTraffic 记录平衡前的总流量，计算平衡前的权重
//   - afterTraffic 记录平衡后的总流量，计算平衡后的权重，包含新增的采集器（流量为 0，分配虚拟流量值，虚拟流量 = 已分配采集器的流量总和 / 已分配采集器总和）
//   - 将新增的采集器加入待重新分配队列
//
// 2、根据总流量，计算每个 analyzer 上平均接收到的流量：avg = afterTraffic / 正常 analyzer 的总数
// 3、遍历已分配数据节点的采集器
//   - 更新数据节点上的总流量: cur = cur + vtap_traffic
//
// 4、遍历数据节点
//   - 数据节点异常：将异常数据节点上的所有采集器加入待重新分配队列
//   - 数据节点正常
//     遍历数据节点上的采集器
//     cur <= avg，跳过
//     cur > avg，如果 agent_num = 1，保持不变；如果 agent_num > 1，将流量最小的采集器加入待重新分配队列，重新遍历采集器直到不满足条件
//
// 5、待重新分配采集器队列按照流量从大到小排列，遍历队列
//   - 遍历数据节点，选择流量最小的数据节点分配给采集器
//   - 直到分配结束
//
// 6、更新数据节点权重
//   - 采集器权重 = 采集器发送流量 / 所有采集器发送的流量
//   - 数据节点的平均权重 = 采集器权重之和 / 正常数据节点个数
//   - 数据节点权重 = 数据节点上的采集器权重之和 / 数据节点的平均权重
func (p *AZInfo) rebalanceAnalyzer(ifCheckout bool) (map[int]*ChangeInfo, *model.AZVTapRebalanceResult) {

	var beforeTraffic, afterTraffic int64
	for _, dataSize := range p.vTapIDToTraffic {
		afterTraffic += dataSize
	}
	beforeTraffic = afterTraffic
	var vtapWithAnalyzerSum int
	for _, vtap := range p.vtaps {
		if vtap.AnalyzerIP != "" {
			vtapWithAnalyzerSum++
		}
	}
	var agentUnassignedTraffic int64
	if vtapWithAnalyzerSum != 0 {
		agentUnassignedTraffic = afterTraffic / int64(vtapWithAnalyzerSum)
	}
	// all vtap news, add virtual traffic
	if afterTraffic == 0 {
		agentUnassignedTraffic = 100
	}
	for id := range p.vTapIDToTraffic {
		if p.vTapIDToTraffic[id] == 0 {
			p.vTapIDToTraffic[id] = agentUnassignedTraffic
			afterTraffic += p.vTapIDToTraffic[id]
		}
	}

	type VTapInfo struct {
		VtapID  int
		Traffic int64
	}
	type Info struct {
		State        int
		SumTraffic   int64
		AfterVTapNum int
		VTapInfos    []VTapInfo
	}

	var completeAnalyzerNum int
	azVTapRebalanceResult := &model.AZVTapRebalanceResult{}
	analyzerIPToInfo := make(map[string]*Info, len(p.analyzers))
	for _, analyzer := range p.analyzers {
		if analyzer.State == common.HOST_STATE_COMPLETE {
			completeAnalyzerNum++
		}
		detail := &model.HostVTapRebalanceResult{
			IP:    analyzer.IP,
			AZ:    p.lcuuid,
			State: analyzer.State,
		}
		analyzerIPToInfo[analyzer.IP] = &Info{State: analyzer.State}
		azVTapRebalanceResult.Details = append(azVTapRebalanceResult.Details, detail)
	}

	var allocVTaps []VTapInfo
	vTapIDToChangeInfo := make(map[int]*ChangeInfo, len(p.vtaps))
	if len(p.vtaps) == 0 {
		log.Warningf("no vtaps to alloc analyzer")
		return nil, nil
	}
	vtapaAerageTraffic := float64(afterTraffic) / float64(len(p.vtaps))
	for _, vtap := range p.vtaps {
		w, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(p.vTapIDToTraffic[vtap.ID])/vtapaAerageTraffic), 64)
		if vtap.AnalyzerIP == "" {
			vTapIDToChangeInfo[vtap.ID] = &ChangeInfo{OldIP: "", NewWeight: w}
			allocVTaps = append(allocVTaps, VTapInfo{VtapID: vtap.ID, Traffic: p.vTapIDToTraffic[vtap.ID]})
			continue
		}
		vTapIDToChangeInfo[vtap.ID] = &ChangeInfo{OldIP: vtap.AnalyzerIP, NewIP: vtap.AnalyzerIP, NewWeight: w}

		// the analyzer ip in getting vtap traffic data is not in the analyzer table
		if _, ok := analyzerIPToInfo[vtap.AnalyzerIP]; !ok {
			allocVTaps = append(allocVTaps, VTapInfo{VtapID: vtap.ID, Traffic: p.vTapIDToTraffic[vtap.ID]})
			log.Infof("vtap(%v) analyzer ip(%v) is not in analyzer table", vtap.Name, vtap.AnalyzerIP)
			continue
		}
		analyzerIPToInfo[vtap.AnalyzerIP].SumTraffic += p.vTapIDToTraffic[vtap.ID]
		analyzerIPToInfo[vtap.AnalyzerIP].AfterVTapNum++ // hold old vtap num
		analyzerIPToInfo[vtap.AnalyzerIP].VTapInfos = append(analyzerIPToInfo[vtap.AnalyzerIP].VTapInfos,
			VTapInfo{VtapID: vtap.ID, Traffic: p.vTapIDToTraffic[vtap.ID]},
		)

		// beforeWeight counts the actual allocated vtap weight before balancing
		beforeWeight, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(p.vTapIDToTraffic[vtap.ID])/float64(beforeTraffic)), 64)
		for _, detail := range azVTapRebalanceResult.Details {
			if detail.IP != vtap.AnalyzerIP {
				continue
			}
			detail.BeforeVTapNum++
			detail.AfterVTapNum = detail.BeforeVTapNum
			detail.BeforeVTapWeights += beforeWeight
		}
	}

	if completeAnalyzerNum == 0 {
		log.Warningf("no complete analyzer to rebalance vtaps, az(%v)", p.lcuuid)
		return nil, nil
	}
	avg := float64(afterTraffic) / float64(completeAnalyzerNum)
	// adjust over-allocated agents on analyzer
	for ip, info := range analyzerIPToInfo {
		if info.State == common.HOST_STATE_COMPLETE && (float64(info.SumTraffic) <= avg || len(info.VTapInfos) == 1) {
			continue
		}

		// analyzer_sum_data_size > avg && vtap_num > 1
		sort.Slice(info.VTapInfos, func(i, j int) bool {
			return info.VTapInfos[i].Traffic < info.VTapInfos[j].Traffic
		})
		for i := 0; i < len(info.VTapInfos); i++ {
			if info.State == common.HOST_STATE_COMPLETE && (float64(info.SumTraffic) <= avg || i == len(info.VTapInfos)-1) {
				break
			}
			allocVTaps = append(allocVTaps, info.VTapInfos[i])
			info.SumTraffic -= info.VTapInfos[i].Traffic
			analyzerIPToInfo[ip].AfterVTapNum--
		}
	}

	sort.Slice(allocVTaps, func(i, j int) bool {
		return allocVTaps[i].Traffic > allocVTaps[j].Traffic
	})
	for _, allocVTap := range allocVTaps {
		var minAnalyzerDataSize int64
		var allocIP string
		for ip, info := range analyzerIPToInfo {
			if info.State != common.HOST_STATE_COMPLETE {
				continue
			}
			minAnalyzerDataSize = info.SumTraffic
			allocIP = ip
			break
		}
		for ip, info := range analyzerIPToInfo {
			if info.State != common.HOST_STATE_COMPLETE {
				continue
			}
			if info.SumTraffic < minAnalyzerDataSize {
				minAnalyzerDataSize = info.SumTraffic
				allocIP = ip
			}
		}
		if !ifCheckout {
			mysql.Db.Model(mysql.VTap{}).Where("id = ?", allocVTap.VtapID).Update("analyzer_ip", allocIP)
		}
		if _, ok := analyzerIPToInfo[allocIP]; !ok {
			log.Warningf("allocate vtap(%d) failed, wanted analyzer ip", allocVTap.VtapID, allocIP)
			continue
		}
		analyzerIPToInfo[allocIP].SumTraffic += allocVTap.Traffic
		analyzerIPToInfo[allocIP].AfterVTapNum++
		vTapIDToChangeInfo[allocVTap.VtapID].NewIP = allocIP
	}

	var totalSwitchVTapNum int
	var beforeWeight, afterWeight float64
	for _, detail := range azVTapRebalanceResult.Details {
		info, ok := analyzerIPToInfo[detail.IP]
		if !ok {
			log.Errorf("can not find response data(analyzer ip: %s)", detail.IP)
			continue
		}
		detail.AfterVTapNum = info.AfterVTapNum
		detail.SwitchVTapNum = int(math.Abs(float64(detail.AfterVTapNum - detail.BeforeVTapNum)))
		w, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", float64(info.SumTraffic)/float64(afterTraffic)), 64)
		detail.AfterVTapWeights = w
		w, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", detail.BeforeVTapWeights), 64)
		detail.BeforeVTapWeights = w

		totalSwitchVTapNum += detail.SwitchVTapNum
		beforeWeight += detail.BeforeVTapWeights
		afterWeight += detail.AfterVTapWeights
	}
	azVTapRebalanceResult.TotalSwitchVTapNum = totalSwitchVTapNum

	avgBeforeWeight := beforeWeight / float64(completeAnalyzerNum)
	avgAfterWeight := afterWeight / float64(completeAnalyzerNum)
	for _, detail := range azVTapRebalanceResult.Details {
		if avgBeforeWeight != 0 {
			w, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", detail.BeforeVTapWeights/avgBeforeWeight), 64)
			detail.BeforeVTapWeights = w
		}
		if avgAfterWeight != 0 {
			w, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", detail.AfterVTapWeights/avgAfterWeight), 64)
			detail.AfterVTapWeights = w
		}
	}
	return vTapIDToChangeInfo, azVTapRebalanceResult
}

func (r *AnalyzerInfo) getVTapTraffic(dataDuration int, regionToAZLcuuids map[string][]string) (map[string]map[string]int64, error) {
	ipToController := make(map[string]*mysql.Controller)
	for i, controller := range r.dbInfo.Controllers {
		ipToController[controller.IP] = &r.dbInfo.Controllers[i]
	}

	azToControllers := make(map[string][]*mysql.Controller)
	for _, conn := range r.dbInfo.AZControllerConns {
		if conn.AZ == "ALL" {
			if azLcuuids, ok := regionToAZLcuuids[conn.Region]; ok {
				for _, azLcuuid := range azLcuuids {
					if controller, ok := ipToController[conn.ControllerIP]; ok {
						azToControllers[azLcuuid] = append(
							azToControllers[azLcuuid], controller)
					}
				}
			}
		} else {
			if controller, ok := ipToController[conn.ControllerIP]; ok {
				azToControllers[conn.AZ] = append(azToControllers[conn.AZ], controller)
			}
		}
	}

	regionToRegionDomainPrefix := make(map[string]string)
	for _, conn := range r.dbInfo.AZControllerConns {
		if _, ok := regionToRegionDomainPrefix[conn.Region]; ok {
			continue
		}
		if controller, ok := ipToController[conn.ControllerIP]; ok {
			regionToRegionDomainPrefix[conn.Region] = controller.RegionDomainPrefix
		}
	}
	regionToVTapNameToTraffic := make(map[string]map[string]int64)
	for region, domainPrefix := range regionToRegionDomainPrefix {
		vtapNameToTraffic, err := r.query.GetAgentDispatcher(domainPrefix, dataDuration)
		if err != nil {
			log.Errorf("get query data failed, region(%s), err: %s", region, err)
			continue
		}

		if _, ok := regionToVTapNameToTraffic[region]; !ok {
			regionToVTapNameToTraffic[region] = make(map[string]int64)
		}
		regionToVTapNameToTraffic[region] = vtapNameToTraffic
	}
	return regionToVTapNameToTraffic, nil
}

type Query struct{}

func (q *Query) GetAgentDispatcher(domainPrefix string, dataDuration int) (map[string]int64, error) {
	if domainPrefix == "master-" {
		domainPrefix = ""
	}
	queryURL := fmt.Sprintf("http://%sdeepflow-server:%d/v1/query", domainPrefix, config.Cfg.ListenPort)
	values := url.Values{}
	db := "deepflow_system"
	now := time.Now()
	before := now.UTC().Add(time.Second * -1 * time.Duration(dataDuration))
	sql := fmt.Sprintf("SELECT `tag.host`, Sum(`metrics.tx-bytes`) AS `tx-bps` FROM deepflow_agent_collect_sender"+
		" WHERE `time`>%d AND `time`<%d GROUP BY tag.host", before.Unix(), now.Unix())
	values.Add("db", db)
	values.Add("sql", sql)
	t := time.Now()
	resp, err := http.PostForm(queryURL, values)
	if err != nil {
		return nil, fmt.Errorf("curl (%s) failed, db (%s), sql: %s, err: %s", queryURL, db, sql, err)
	}
	defer resp.Body.Close()
	log.Infof("curl(%s) query data time since(%v)", queryURL, time.Since(t))

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, err
	}

	vtapNameToDataSize, err := parseBody(body)
	if err != nil {
		return nil, fmt.Errorf("parse response data failed, data: %s, err: %s", string(body), err)
	}
	return vtapNameToDataSize, nil
}

// column name
const (
	tagHost = "tag.host"
	txBPS   = "tx-bps"
)

// parseBody parse query api response body to vtapNameToTraffic(map[string]int64).
func parseBody(data []byte) (map[string]int64, error) {
	respJson, err := simplejson.NewJson(data)
	if err != nil {
		return nil, err
	}
	optStatus := respJson.Get("OPT_STATUS").MustString()
	if optStatus != "" && optStatus != "SUCCESS" {
		description := respJson.Get("DESCRIPTION").MustString()
		return nil, errors.New(description)
	}

	result := respJson.Get("result")
	columns := result.Get("columns")
	values := result.Get("values")
	vtapNameToTraffic := make(map[string]int64)
	for i := range values.MustArray() {
		value := values.GetIndex(i)
		if columns.GetIndex(0).MustString() == tagHost {
			vtapNameToTraffic[value.GetIndex(0).MustString()] = int64(value.GetIndex(1).MustFloat64())
		} else {
			vtapNameToTraffic[value.GetIndex(1).MustString()] = int64(value.GetIndex(0).MustFloat64())
		}
	}
	return vtapNameToTraffic, nil
}

func updateCounter(vtapIDToVTap map[int]*mysql.VTap, vtapNameToID map[string]int, vtapIDToChangeInfo map[int]*ChangeInfo) {
	setNullFunc := func(name string, vtapNameToCounter map[string]*statsd.GetVTapWeightCounter) {
		if _, ok := statsd.VTapNameToCounter[name]; ok {
			statsd.VTapNameToCounter[name].VTapWeightCounter = &statsd.VTapWeightCounter{}
		}
	}

	for name := range statsd.VTapNameToCounter {
		vtapID, ok := vtapNameToID[name]
		if !ok {
			setNullFunc(name, statsd.VTapNameToCounter)
			continue
		}
		if vtap, ok := vtapIDToVTap[vtapID]; ok && vtap.State != common.VTAP_STATE_NORMAL {
			setNullFunc(name, statsd.VTapNameToCounter)
			continue
		}
	}

	for vtapID, changeInfo := range vtapIDToChangeInfo {
		vtap, ok := vtapIDToVTap[vtapID]
		if !ok {
			log.Info("vtap(%d) not found, change info: %#v", vtapID, changeInfo)
			continue
		}
		name := vtap.Name
		if vtap.State != common.VTAP_STATE_NORMAL {
			setNullFunc(name, statsd.VTapNameToCounter)
			continue
		}

		isAnalyzerChanged := uint64(0)
		if changeInfo.OldIP != changeInfo.NewIP {
			isAnalyzerChanged = uint64(1)
		}
		counter, ok := statsd.VTapNameToCounter[name]
		if !ok {
			counter := &statsd.GetVTapWeightCounter{
				Name: name,
				VTapWeightCounter: &statsd.VTapWeightCounter{
					Weight:            changeInfo.NewWeight,
					IsAnalyzerChanged: isAnalyzerChanged,
				},
			}
			statsd.VTapNameToCounter[name] = counter
			b, _ := json.Marshal(counter)
			log.Infof("agent(%v) register counter: %v", name, string(b))
			err := stats.RegisterCountableWithModulePrefix("controller_", "analyzer_alloc", counter, stats.OptionStatTags{"host": name})
			if err != nil {
				log.Error(err)
			}
		} else {
			log.Infof("agent(%v) update weight: %v -> %v", name, counter.VTapWeightCounter.Weight, changeInfo.NewWeight)
			log.Infof("agent(%v) update is_analyzer_changed: %v -> %v", name, counter.VTapWeightCounter.IsAnalyzerChanged, isAnalyzerChanged)
			counter.VTapWeightCounter.Weight = changeInfo.NewWeight
			counter.VTapWeightCounter.IsAnalyzerChanged = isAnalyzerChanged
		}
	}
}
