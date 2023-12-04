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

package decoder

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cornelk/hashmap"
	"github.com/golang/protobuf/proto"
	"github.com/prometheus/common/model"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	METRICID_OFFSET = 32 // when generate columnIndexKey/metricTargetPairKey, high32 is metricID, low32 can be labelNameID/targetID

	// when generate targetIdKey, high16 is podClusterId, mid24 is JobId, low24 is instanceId
	POD_CLUSTER_ID_OFFSET = 48
	JOBID_OFFSET          = 24
)

func columnIndexKey(metricID, labelNameID uint32) uint64 {
	return uint64(metricID)<<METRICID_OFFSET | uint64(labelNameID)
}

func targetIdKey(podClusterId uint16, jobID, instanceID uint32) uint64 {
	return uint64(podClusterId)<<POD_CLUSTER_ID_OFFSET | uint64(jobID)<<JOBID_OFFSET | uint64(instanceID)
}

func nameValueKey(nameID, valueID uint32) uint64 {
	return uint64(nameID)<<32 | uint64(valueID)
}

func metricTargetPairKey(metricID, targetID uint32) uint64 {
	return uint64(metricID)<<METRICID_OFFSET | uint64(targetID)
}

func (t *PrometheusLabelTable) QueryMetricID(metricName string) (uint32, bool) {
	return t.metricNameIDs.Get(metricName)
}

func (t *PrometheusLabelTable) QueryLabelNameID(labelName string) (uint32, bool) {
	return t.labelNameIDs.Get(labelName)
}

func (t *PrometheusLabelTable) QueryLabelValueID(labelValue string) (uint32, bool) {
	return t.labelValueIDs.Get(labelValue)
}

func (t *PrometheusLabelTable) QueryLabelNameValue(nameId, valueId uint32) bool {
	_, exists := t.labelNameValues.Get(nameValueKey(nameId, valueId))
	return exists
}

func (t *PrometheusLabelTable) QueryColumnIndex(metricID, labelNameID uint32) (uint32, bool) {
	return t.labelColumnIndexs.Get(columnIndexKey(metricID, labelNameID))
}

func (t *PrometheusLabelTable) QueryTargetID(podClusterId uint16, jobID, instanceID uint32) (uint32, bool) {
	return t.targetIDs.Get(targetIdKey(podClusterId, jobID, instanceID))
}

func (t *PrometheusLabelTable) QueryMetricTargetPair(metricID, targetID uint32) bool {
	_, exists := t.metricTargetPair.Get(metricTargetPairKey(metricID, targetID))
	return exists
}

type RequestCounter struct {
	RequestCount        int64  `statsd:"request-count"`
	RequestTotalDelayNs int64  `statsd:"request-total-delay-ns"`
	ResponseFailed      int64  `statsd:"response-failed"`
	RequestLabelsCount  int64  `statsd:"request-labels-count"`
	ResponseLabelsCount int64  `statsd:"response-labels-count"`
	MetricUnknown       uint64 `statsd:"metric-unknown"`
	TargetIdZero        uint64 `statsd:"target-id-zero"`
	LabelNameUnknown    uint64 `statsd:"label-name-unknown"`
	LabelValueUnknown   uint64 `statsd:"label-value-unknown"`
}

func (t *PrometheusLabelTable) GetCounter() interface{} {
	var counter *RequestCounter
	counter, t.counter = t.counter, &RequestCounter{}
	return counter
}

type PrometheusLabelTable struct {
	ctlIP       string
	GrpcSession *grpc.GrpcSession

	metricNameIDs     *hashmap.Map[string, uint32]
	labelNameIDs      *hashmap.Map[string, uint32]
	labelValueIDs     *hashmap.Map[string, uint32]
	labelNameValues   *hashmap.Map[uint64, struct{}]
	labelColumnIndexs *hashmap.Map[uint64, uint32]
	targetIDs         *hashmap.Map[uint64, uint32]
	metricTargetPair  *hashmap.Map[uint64, struct{}]
	targetLabelIDs    *hashmap.Map[uint32, []uint32]
	targetVersion     uint32

	counter *RequestCounter
	utils.Closable
}

func NewPrometheusLabelTable(controllerIPs []string, port, rpcMaxMsgSize int) *PrometheusLabelTable {
	ips := make([]net.IP, len(controllerIPs))
	for i, ipString := range controllerIPs {
		ips[i] = net.ParseIP(ipString)
		if ips[i].To4() != nil {
			ips[i] = ips[i].To4()
		}
	}
	t := &PrometheusLabelTable{
		GrpcSession:       &grpc.GrpcSession{},
		metricNameIDs:     hashmap.New[string, uint32](),   // metricName => metricID
		labelNameIDs:      hashmap.New[string, uint32](),   // labelName  => labelNameID
		labelValueIDs:     hashmap.New[string, uint32](),   // labelValue => labelValueID
		labelNameValues:   hashmap.New[uint64, struct{}](), // labelNameValue => exists
		labelColumnIndexs: hashmap.New[uint64, uint32](),   // metricID + LabelNameID => columnIndex
		targetIDs:         hashmap.New[uint64, uint32](),   // jobID + instanceID => targetID
		metricTargetPair:  hashmap.New[uint64, struct{}](), // metricID + targetID => exists
		targetLabelIDs:    hashmap.New[uint32, []uint32](), // targetID => targetLabelIDs
		counter:           &RequestCounter{},
	}
	t.GrpcSession.Init(ips, uint16(port), grpc.DEFAULT_SYNC_INTERVAL, rpcMaxMsgSize, nil)
	log.Infof("New PrometheusLabelTable ips:%v port:%d rpcMaxMsgSize:%d", ips, port, rpcMaxMsgSize)
	debug.ServerRegisterSimple(ingesterctl.CMD_PROMETHEUS_LABEL, t)
	common.RegisterCountableForIngester("prometheus-label-request", t)
	go t.UpdateTargetIdsRegularIntervals()
	return t
}

func (t *PrometheusLabelTable) UpdateTargetIdsRegularIntervals() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		t.RequestAllTargetIDs()
	}
}

func (t *PrometheusLabelTable) RequestAllTargetIDs() {
	var response *trident.PrometheusTargetResponse
	err := t.GrpcSession.Request(func(ctx context.Context, remote net.IP) error {
		var err error
		c := t.GrpcSession.GetClient()
		if c == nil {
			return fmt.Errorf("can't get grpc client to %s", remote)
		}
		client := trident.NewSynchronizerClient(c)
		response, err = client.GetPrometheusTargets(ctx, &trident.PrometheusTargetRequest{Version: proto.Uint32(t.targetVersion)})
		return err
	})
	if err != nil {
		log.Warningf("request all prometheus target ids failed: %s", err)
		return
	}
	newVersion := response.GetVersion()
	if t.targetVersion != newVersion {
		log.Infof("prometheus update target version update from %d to %d", t.targetVersion, newVersion)
		t.targetVersion = newVersion
		targetIds := response.GetResponseTargetIds()
		t.updateDroppedTargets(t.getPrometheusDroppedTargets(targetIds))
		t.updatePrometheusTargets(targetIds)
	}
}

func (t *PrometheusLabelTable) RequestLabelIDs(request *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	t.counter.RequestCount++
	t.counter.RequestLabelsCount += int64(len(request.GetRequestLabels()))
	var response *trident.PrometheusLabelResponse
	requestStart := time.Now()
	err := t.GrpcSession.Request(func(ctx context.Context, remote net.IP) error {
		var err error
		c := t.GrpcSession.GetClient()
		if c == nil {
			return fmt.Errorf("can't get grpc client to %s", remote)
		}
		client := trident.NewSynchronizerClient(c)
		response, err = client.GetPrometheusLabelIDs(ctx, request)
		return err
	})
	if err != nil {
		t.counter.ResponseFailed++
		return nil, err
	}

	t.counter.ResponseLabelsCount += int64(len(response.GetResponseLabelIds()))
	t.counter.RequestTotalDelayNs += int64(time.Since(requestStart))
	t.updatePrometheusLabels(response)

	return response, nil
}

func (t *PrometheusLabelTable) RequestAllLabelIDs() {
	log.Info("prometheus request all label IDs start")
	_, err := t.RequestLabelIDs(&trident.PrometheusLabelRequest{})
	if err != nil {
		log.Warning("request all prometheus label ids failed: %s", err)
	}
	log.Infof("prometheus request all label IDs end. %s", t.statsString())
}

// When the Target is deleted, the data in the corresponding table of the Target needs to be deleted
// otherwise, if the label type of the target changes from target type to app type, it cannot be updated.
func (t *PrometheusLabelTable) updateDroppedTargets(droppedTargetIds []uint32, droppedTargetIdKeys []uint64) {
	if len(droppedTargetIds) == 0 {
		return
	}

	for _, droppedTargeIdKey := range droppedTargetIdKeys {
		t.targetIDs.Del(droppedTargeIdKey)
	}
	log.Infof("prometheus update target_ids drop(%v)", droppedTargetIds)

	droppedTargetMetricKeys, droppedMetriIds := []uint64{}, []uint32{}
	t.metricTargetPair.Range(func(k uint64, v struct{}) bool {
		for _, droppedTargetId := range droppedTargetIds {
			if uint32(k) == droppedTargetId {
				droppedTargetMetricKeys = append(droppedTargetMetricKeys, k)
				droppedMetriIds = append(droppedMetriIds, uint32(k>>METRICID_OFFSET))
				break
			}
		}
		return true
	})
	for _, droppedTargetMetricKey := range droppedTargetMetricKeys {
		t.metricTargetPair.Del(droppedTargetMetricKey)
	}
	if len(droppedTargetMetricKeys) > 0 {
		log.Infof("prometheus update target_metrics drop metricIds(%v), drop targetMetric(%v)", droppedMetriIds, droppedTargetMetricKeys)
	}

	droppedColumnIndexKeys := []uint64{}
	t.labelColumnIndexs.Range(func(k uint64, v uint32) bool {
		metricId := uint32(k >> METRICID_OFFSET)
		for _, droppedMetricId := range droppedMetriIds {
			if metricId == droppedMetricId {
				droppedColumnIndexKeys = append(droppedColumnIndexKeys, k)
				break
			}
		}
		return true
	})

	for _, columnIndexKey := range droppedColumnIndexKeys {
		t.labelColumnIndexs.Del(columnIndexKey)
	}
	if len(droppedColumnIndexKeys) > 0 {
		log.Infof("prometheus update drop column_indexs(%v)", droppedColumnIndexKeys)
	}
}

// if the target_id is not in the new target list, it means that the target has been dropped.
func (t *PrometheusLabelTable) getPrometheusDroppedTargets(targetIds []*trident.TargetResponse) (droppedTargetIds []uint32, droppedTargetIdKeys []uint64) {
	t.targetIDs.Range(func(k uint64, v uint32) bool {
		find := false
		for _, target := range targetIds {
			if v == target.GetTargetId() {
				find = true
				break
			}
		}
		if !find {
			droppedTargetIds = append(droppedTargetIds, v)
			droppedTargetIdKeys = append(droppedTargetIdKeys, k)
		}
		return true
	})
	return
}

func (t *PrometheusLabelTable) updatePrometheusTargets(targetIds []*trident.TargetResponse) {
	for _, target := range targetIds {
		targetId := target.GetTargetId()
		if targetId == 0 {
			if t.counter.TargetIdZero == 0 {
				log.Infof("prometheus label response target id 0: %s", target)
			}
			t.counter.TargetIdZero++
		}
		jobId := target.GetJobId()
		instanceId := target.GetInstanceId()
		podClusterId := target.GetPodClusterId()
		t.labelValueIDs.Set(strings.Clone(target.GetJob()), jobId)
		t.labelValueIDs.Set(strings.Clone(target.GetInstance()), instanceId)
		for _, metricId := range target.GetMetricIds() {
			t.metricTargetPair.Set(metricTargetPairKey(metricId, targetId), struct{}{})
		}
		t.targetIDs.Set(targetIdKey(uint16(podClusterId), jobId, instanceId), targetId)
		t.updateTargetLabelIds(targetId, target.GetTargetLabelNameIds())
	}
}

func u32SliceIsEqual(l, r []uint32) bool {
	if len(l) != len(r) {
		return false
	}
	for i := range l {
		if l[i] != r[i] {
			return false
		}
	}
	return true
}

// get elements that appear only once in the two slices
func uniqueElements(slice1, slice2 []uint32) map[uint32]bool {
	unique := make(map[uint32]bool)

	for _, v1 := range slice1 {
		unique[v1] = true
	}

	for _, v2 := range slice2 {
		if _, ok := unique[v2]; !ok {
			unique[v2] = true
		} else {
			delete(unique, v2)
		}
	}

	return unique
}

// if the target labels of the target change, the label column index needs to be updated
func (t *PrometheusLabelTable) updateTargetLabelIds(targetId uint32, targetLabelIDs []uint32) {
	oldLabelIds, ok := t.targetLabelIDs.Get(targetId)
	if !ok {
		// if not found, it means that it is a newly added target
		ids := make([]uint32, 0, len(targetLabelIDs))
		ids = append(ids, targetLabelIDs...)
		t.targetLabelIDs.Set(targetId, ids)
		return
	}
	// check equal first
	if u32SliceIsEqual(oldLabelIds, targetLabelIDs) {
		return
	}
	uniqueLabelIds := uniqueElements(oldLabelIds, targetLabelIDs)

	// check all metric of target
	t.metricTargetPair.Range(func(k uint64, v struct{}) bool {
		if uint32(k) == targetId {
			metricId := uint32(k >> METRICID_OFFSET)
			// delete the label column index information, it will update when receive the data
			for labelId := range uniqueLabelIds {
				t.labelColumnIndexs.Del(columnIndexKey(metricId, labelId))
			}
		}
		return true
	})
	log.Infof("prometheus update target labels of target_id(%d) from %+v to %+v", targetId, oldLabelIds, targetLabelIDs)
	newLabelIds := oldLabelIds[:0]
	newLabelIds = append(newLabelIds, targetLabelIDs...)
	t.targetLabelIDs.Set(targetId, newLabelIds)
}

func (t *PrometheusLabelTable) updatePrometheusLabels(resp *trident.PrometheusLabelResponse) {
	t.updatePrometheusTargets(resp.GetResponseTargetIds())

	for _, metric := range resp.GetResponseLabelIds() {
		metricName := metric.GetMetricName()
		if metricName == "" {
			t.counter.MetricUnknown++
			continue
		}
		metricId := metric.GetMetricId()
		t.metricNameIDs.Set(strings.Clone(metricName), metricId)
		var jobId, instanceId uint32
		for _, labelInfo := range metric.GetLabelIds() {
			name := labelInfo.GetName()
			nameId := labelInfo.GetNameId()
			if name != "" && nameId != 0 {
				t.labelNameIDs.Set(strings.Clone(name), nameId)
			} else {
				t.counter.LabelNameUnknown++
			}
			value := labelInfo.GetValue()
			valueId := labelInfo.GetValueId()
			if valueId != 0 {
				t.labelValueIDs.Set(strings.Clone(value), valueId)
			} else {
				t.counter.LabelValueUnknown++
			}
			if jobId == 0 && name == model.JobLabel {
				jobId = valueId
			} else if instanceId == 0 && name == model.InstanceLabel {
				instanceId = valueId
			}
			t.labelNameValues.Set(nameValueKey(nameId, valueId), struct{}{})

			cIndex := labelInfo.GetAppLabelColumnIndex()
			t.labelColumnIndexs.Set(columnIndexKey(metricId, nameId), cIndex)
		}

		// when response all metric labels at starting, pod cluster id is 0
		podClusterId := metric.GetPodClusterId()
		if podClusterId == 0 {
			continue
		}
		targetId, ok := t.targetIDs.Get(targetIdKey(uint16(podClusterId), jobId, instanceId))
		if !ok {
			if t.counter.TargetIdZero == 0 {
				log.Warningf("prometheus label response label target invalid: jobId: %d, instanceId: %d, metric: %s", jobId, instanceId, metric)
			}
			t.counter.TargetIdZero++
			continue
		}
		if _, ok := t.metricTargetPair.Get(metricTargetPairKey(metricId, targetId)); !ok {
			t.metricTargetPair.Set(metricTargetPairKey(metricId, targetId), struct{}{})
		}
	}
}

func (t *PrometheusLabelTable) GetMaxAppLabelColumnIndex() int {
	return int(getUInt64MapMaxValue(t.labelColumnIndexs))
}

func (t *PrometheusLabelTable) metricIDsString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\nmetricName                                                                                            metricId\n")
	sb.WriteString("---------------------------------------------------------------------------------------------------------------\n")
	t.metricNameIDs.Range(func(k string, v uint32) bool {
		row := fmt.Sprintf("%-100s  %d\n", k, v)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true
	})
	return sb.String()
}

func (t *PrometheusLabelTable) nameIDsString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\nname                                                              nameId\n")
	sb.WriteString("--------------------------------------------------------------------------\n")
	t.labelNameIDs.Range(func(k string, v uint32) bool {
		row := fmt.Sprintf("%-64s  %d\n", k, v)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true
	})
	return sb.String()
}

func (t *PrometheusLabelTable) valueIDsString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\nvalue                                                                                                                             valueId\n")
	sb.WriteString("--------------------------------------------------------------------------------------------------------------------------------------------\n")
	t.labelValueIDs.Range(func(k string, v uint32) bool {
		row := fmt.Sprintf("%-128s  %d\n", k, v)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true
	})
	return sb.String()
}

func (t *PrometheusLabelTable) columnIndexString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\ncolumnIndex  metricName                                                                                            metricId   name                                                              nameId\n")
	sb.WriteString("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
	t.labelColumnIndexs.Range(func(k uint64, v uint32) bool {
		metricId := k >> METRICID_OFFSET
		nameId := k << (64 - METRICID_OFFSET) >> (64 - METRICID_OFFSET)
		metricName, name := "", ""
		t.metricNameIDs.Range(func(n string, i uint32) bool {
			if i == uint32(metricId) {
				metricName = n
				return false
			}
			return true
		})
		t.labelNameIDs.Range(func(n string, i uint32) bool {
			if i == uint32(nameId) {
				name = n
				return false
			}
			return true
		})
		row := fmt.Sprintf("%-11d  %-100s  %-9d  %-64s  %-6d\n", v, metricName, metricId, name, nameId)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true
	})
	return sb.String()
}

func (t *PrometheusLabelTable) targetString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\ntargetId     clusterId  job                                                              jobId    instance                             instanceId                       target_label_ids\n")
	sb.WriteString("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

	t.targetIDs.Range(func(k uint64, v uint32) bool {
		podClusterId := k >> POD_CLUSTER_ID_OFFSET
		jobId := k << (64 - POD_CLUSTER_ID_OFFSET) >> (64 - POD_CLUSTER_ID_OFFSET) >> JOBID_OFFSET
		instanceId := k << (64 - JOBID_OFFSET) >> (64 - JOBID_OFFSET)
		job, instance := "", ""
		t.labelValueIDs.Range(func(n string, i uint32) bool {
			if i == uint32(jobId) {
				job = n
			} else if i == uint32(instanceId) {
				instance = n
			}
			if job != "" && instance != "" {
				return false
			}
			return true
		})
		targetLabebs, _ := t.targetLabelIDs.Get(v)
		row := fmt.Sprintf("%-10d   %-9d  %-64s  %-5d   %-32s     %-32d %v\n", v, podClusterId, job, jobId, instance, instanceId, targetLabebs)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true

	})
	return sb.String()
}

func getStringMapMaxValue(m *hashmap.Map[string, uint32]) uint32 {
	maxId := uint32(0)
	m.Range(func(n string, i uint32) bool {
		if i > maxId {
			maxId = i
		}
		return true
	})
	return maxId
}

func getUInt64MapMaxValue(m *hashmap.Map[uint64, uint32]) uint32 {
	maxId := uint32(0)
	m.Range(func(n uint64, i uint32) bool {
		if i > maxId {
			maxId = i
		}
		return true
	})
	return maxId
}

func (t *PrometheusLabelTable) statsString() string {
	sb := &strings.Builder{}
	sb.WriteString("\ntableType  total-count  max-id\n")
	sb.WriteString("--------------------------------\n")
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "metric", t.metricNameIDs.Len(), getStringMapMaxValue(t.metricNameIDs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "name", t.labelNameIDs.Len(), getStringMapMaxValue(t.labelNameIDs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "value", t.labelValueIDs.Len(), getStringMapMaxValue(t.labelValueIDs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "column", t.labelColumnIndexs.Len(), getUInt64MapMaxValue(t.labelColumnIndexs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "target", t.targetIDs.Len(), getUInt64MapMaxValue(t.targetIDs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d\n", "tgtMtr", t.metricTargetPair.Len()))
	return sb.String()
}

func (t *PrometheusLabelTable) HandleSimpleCommand(op uint16, arg string) string {
	cmd := labelCmds[op]
	switch cmd {
	case "metric":
		return t.metricIDsString(arg)
	case "name":
		return t.nameIDsString(arg)
	case "value":
		return t.valueIDsString(arg)
	case "column":
		return t.columnIndexString(arg)
	case "target":
		return t.targetString(arg)
	case "stats":
		return t.statsString()
	case "test":
		return t.testString(arg)
	case "explain":
		return t.explainString(arg)
	}
	return t.statsString()
}

// request string as: metric=xxx,job=xxx,instance=xxx,label1=xxx,label2=xxx
func (t *PrometheusLabelTable) testString(request string) string {
	req := &trident.PrometheusLabelRequest{}
	metricReq := &trident.MetricLabelRequest{}
	targetReq := &trident.TargetRequest{}
	keyValues := strings.Split(request, ",")
	clusterId := 0
	for _, kv := range keyValues {
		kv := strings.Split(kv, "=")
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "metric" {
			metricReq.MetricName = &(kv[1])
		} else if kv[0] == "job" {
			job := kv[1]
			targetReq.Job = &job
			addLabel(metricReq, kv[0], kv[1])
		} else if kv[0] == "instance" {
			instance := kv[1]
			targetReq.Instance = &instance
			addLabel(metricReq, kv[0], kv[1])
		} else if kv[0] == "clusterId" {
			clusterId, _ = strconv.Atoi(kv[1])
		} else {
			addLabel(metricReq, kv[0], kv[1])
		}
	}
	metricReq.PodClusterId = proto.Uint32(uint32(clusterId))
	targetReq.PodClusterId = proto.Uint32(uint32(clusterId))
	req.RequestLabels = append(req.RequestLabels, metricReq)
	req.RequestTargets = append(req.RequestTargets, targetReq)
	resp, err := t.RequestLabelIDs(req)
	if err != nil {
		return fmt.Sprintf("request: %s\nresponse failed: %s", req, err)
	}
	return fmt.Sprintf("request: %s\nresponse: %s", req, resp)
}

// explain string as: xxx|xxx|xxxx|xxxx|...,   means: metric_id|target_id|app_label_value_id_1|app_label_value_id_2|...
func (t *PrometheusLabelTable) explainString(str string) string {
	values := strings.Split(str, "|")
	intValues := []int{}
	for _, v := range values {
		i := strings.TrimSpace(v)
		if len(i) > 0 {
			integer, _ := strconv.Atoi(i)
			intValues = append(intValues, integer)
		}
	}
	explainStr, explainedStr := "", ""
	for i, v := range intValues {
		if i == 0 {
			explainStr += fmt.Sprintf("metric_id=%d,", v)
		} else if i == 1 {
			explainStr += fmt.Sprintf("target_id=%d,", v)
		} else {
			explainStr += fmt.Sprintf("app_label_value_id_%d=%d,", i-1, v)
		}
	}
	metricName, job, instance := "", "", ""
	if len(intValues) < 1 || intValues[0] == 0 {
		return fmt.Sprintf("invalid metric_id, %s", explainStr)
	}
	metricId := intValues[0]
	t.metricNameIDs.Range(func(n string, i uint32) bool {
		if i == uint32(metricId) {
			metricName = n
			return false
		}
		return true
	})

	if len(intValues) < 2 || intValues[1] == 0 {
		return fmt.Sprintf("invalid target_id, %s", explainStr)
	}
	targetId := uint32(intValues[1])
	t.targetIDs.Range(func(k uint64, v uint32) bool {
		if v != targetId {
			return true
		}
		jobId := k << (64 - POD_CLUSTER_ID_OFFSET) >> (64 - POD_CLUSTER_ID_OFFSET) >> JOBID_OFFSET
		instanceId := k << (64 - JOBID_OFFSET) >> (64 - JOBID_OFFSET)
		t.labelValueIDs.Range(func(n string, i uint32) bool {
			if i == uint32(jobId) {
				job = n
			} else if i == uint32(instanceId) {
				instance = n
			}
			if job != "" && instance != "" {
				return false
			}
			return true
		})
		return false
	})

	names, values := make([]string, len(intValues)-1), make([]string, len(intValues)-1)

	for i, valueId := range intValues[2:] {
		t.labelColumnIndexs.Range(func(k uint64, v uint32) bool {
			mid := k >> METRICID_OFFSET
			if uint64(metricId) != mid {
				return true
			}
			if v == uint32(i+1) {
				nameId := k << (64 - METRICID_OFFSET) >> (64 - METRICID_OFFSET)
				name, value := "", ""
				t.labelNameIDs.Range(func(n string, i uint32) bool {
					if i == uint32(nameId) {
						name = n
						return false
					}
					return true
				})
				t.labelValueIDs.Range(func(n string, i uint32) bool {
					if i == uint32(valueId) {
						value = n
						return false
					}
					return true
				})
				names[v] = name
				values[v] = value
				return false
			}
			return true
		})

	}

	explainedStr += fmt.Sprintf("metric=%s,job=%s,instance=%s,", metricName, job, instance)
	for i := range names {
		if i == 0 {
			continue
		}
		explainedStr += fmt.Sprintf("[%d]%s=%s,", i, names[i], values[i])
	}

	return fmt.Sprintf("explain: %s\nexplained: %s", explainStr, explainedStr)
}

var labelCmds = []string{"metric", "name", "value", "column", "target", "stats", "test", "explain"}
var cmdHelps = []string{"[filter]", "[filter]", "[filter]", "[filter]", "[filter]", "", "metric=xxx,job=xxx,instance=xxx,label1=xxx,label2=xxx", "xxx|xxx|xxxx|xxxx|..., means: metric_id|target_id|app_label_value_id_1|app_label_value_id_2|..."}

func RegisterClientPrometheusLabelCommand() *cobra.Command {
	operates := []debug.CmdHelper{}
	for i, cmd := range labelCmds {
		operates = append(operates, debug.CmdHelper{Cmd: cmd, Helper: cmdHelps[i]})
	}

	return debug.ClientRegisterSimple(ingesterctl.CMD_PROMETHEUS_LABEL,
		debug.CmdHelper{
			Cmd:    "label",
			Helper: "show prometheus label info",
		},
		operates,
	)
}
