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
	"github.com/pyroscope-io/pyroscope/pkg/scrape/model"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	CMD_PROMETHEUS_LABEL = 38
	METRICID_OFFSET      = 42 // metricID max 1<<22
	JOBID_OFFSET         = 32 // jobID/instanceID max 1<<32
)

func columnIndexKey(metricID, nameID uint32) uint64 {
	return uint64(metricID)<<METRICID_OFFSET | uint64(nameID)
}

func targetIdKey(jobID, instanceID uint32) uint64 {
	return uint64(jobID)<<JOBID_OFFSET | uint64(instanceID)
}

func (p *PrometheusLabelTable) QueryMetricID(name string) (uint32, bool) {
	return p.metricNameIDs.Get(name)
}

func (p *PrometheusLabelTable) QueryNameID(name string) (uint32, bool) {
	return p.labelNameIDs.Get(name)
}

func (p *PrometheusLabelTable) QueryValueID(value string) (uint32, bool) {
	return p.labelValueIDs.Get(value)
}

func (p *PrometheusLabelTable) QueryColumnIndex(metricID, nameID uint32) (uint32, bool) {
	return p.labelColumnIndexs.Get(columnIndexKey(metricID, nameID))
}

func (p *PrometheusLabelTable) QueryTargetID(jobID, instanceID uint32) (uint32, bool) {
	return p.targetIDs.Get(targetIdKey(jobID, instanceID))
}

type RequestCounter struct {
	RequestCount        int64  `statsd:"request-count"`
	RequestTimeNs       int64  `statsd:"request-time-ns"`
	ResponseFailed      int64  `statsd:"response-failed"`
	RequestLabelsCount  int64  `statsd:"request-labels-count"`
	ResponseLabelsCount int64  `statsd:"response-labels-count"`
	MetricInvalid       uint64 `statsd:"metric-invalid"`
	TargetInvalid       uint64 `statsd:"target-invalid"`
	NameInvalid         uint64 `statsd:"name-invalid"`
	ValueInvalid        uint64 `statsd:"value-invalid"`
}

func (p *PrometheusLabelTable) GetCounter() interface{} {
	var counter *RequestCounter
	counter, p.counter = p.counter, &RequestCounter{}
	return counter
}

type PrometheusLabelTable struct {
	ctlIP               string
	GrpcSession         *grpc.GrpcSession
	versionPlatformData uint64

	metricNameIDs     *hashmap.Map[string, uint32]
	labelNameIDs      *hashmap.Map[string, uint32]
	labelValueIDs     *hashmap.Map[string, uint32]
	labelColumnIndexs *hashmap.Map[uint64, uint32]
	targetIDs         *hashmap.Map[uint64, uint32]

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
	p := &PrometheusLabelTable{
		GrpcSession:       &grpc.GrpcSession{},
		metricNameIDs:     hashmap.New[string, uint32](),
		labelNameIDs:      hashmap.New[string, uint32](),
		labelValueIDs:     hashmap.New[string, uint32](),
		labelColumnIndexs: hashmap.New[uint64, uint32](),
		targetIDs:         hashmap.New[uint64, uint32](),
		counter:           &RequestCounter{},
	}
	p.GrpcSession.Init(ips, uint16(port), grpc.DEFAULT_SYNC_INTERVAL, rpcMaxMsgSize, nil)
	log.Infof("New PrometheusLabelTable ips:%v port:%d rpcMaxMsgSize:%d", ips, port, rpcMaxMsgSize)
	debug.ServerRegisterSimple(CMD_PROMETHEUS_LABEL, p)
	common.RegisterCountableForIngester("prometheus-label-request", p)
	return p
}

var rCount uint32

func (p *PrometheusLabelTable) RequesteLabelIDs(request *trident.PrometheusLabelIDsRequest) (*trident.PrometheusLabelIDsResponse, error) {
	p.counter.RequestCount++
	p.counter.RequestLabelsCount += int64(len(request.GetRequestLabels()))
	var response *trident.PrometheusLabelIDsResponse
	requestStart := time.Now()
	err := p.GrpcSession.Request(func(ctx context.Context, remote net.IP) error {
		var err error
		c := p.GrpcSession.GetClient()
		if c == nil {
			return fmt.Errorf("can't get grpc client to %s", remote)
		}
		client := trident.NewSynchronizerClient(c)
		response, err = client.GetPrometheusLabelIDs(ctx, request)
		return err
	})
	if err != nil {
		p.counter.ResponseFailed++
		return nil, err
	}

	if rCount%200 == 0 {
		log.Infof("request ====: %s response ====: %s", request, response)
	}
	rCount++
	p.counter.ResponseLabelsCount += int64(len(response.GetResponseLabelIds()))
	p.counter.RequestTimeNs += int64(time.Since(requestStart))
	p.updatePrometheusLabels(response)

	return response, nil
}

func (p *PrometheusLabelTable) RequesteAllLabelIDs() {
	_, err := p.RequesteLabelIDs(&trident.PrometheusLabelIDsRequest{})
	if err != nil {
		log.Warning("request all prometheus label ids failed: %s", err)
	}
}

func (p *PrometheusLabelTable) updatePrometheusLabels(resp *trident.PrometheusLabelIDsResponse) {
	for _, metric := range resp.GetResponseLabelIds() {
		metricName := metric.GetMetricName()
		if metricName == "" {
			p.counter.MetricInvalid++
			continue
		}
		metricId := metric.GetMetricId()
		p.metricNameIDs.Set(metricName[:], metricId)
		var jobId, instanceId uint32
		for _, labelInfo := range metric.GetLabelIds() {
			name := labelInfo.GetName()
			nameId := labelInfo.GetNameId()
			if name != "" && nameId != 0 {
				p.labelNameIDs.Set(name[:], nameId)
			} else {
				p.counter.NameInvalid++
			}
			value := labelInfo.GetValue()
			valueId := labelInfo.GetValueId()
			if value != "" && valueId != 0 {
				p.labelValueIDs.Set(value[:], valueId)
			} else {
				p.counter.ValueInvalid++
			}
			if name == model.JobLabel {
				jobId = valueId
			} else if name == model.InstanceLabel {
				instanceId = valueId
			}
			cIndex := labelInfo.GetAppLabelColumnIndex()
			p.labelColumnIndexs.Set(columnIndexKey(metricId, nameId), cIndex)
		}
		targetId := metric.GetTargetId()
		if targetId == 0 {
			p.counter.TargetInvalid++
			continue
		}
		if jobId > 0 || instanceId > 0 {
			p.targetIDs.Set(targetIdKey(jobId, instanceId), targetId)
		}
	}
}

func (p *PrometheusLabelTable) metricIDsString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\nmetricName                                                                                            metricId\n")
	sb.WriteString("---------------------------------------------------------------------------------------------------------------\n")
	p.metricNameIDs.Range(func(k string, v uint32) bool {
		row := fmt.Sprintf("%-100s  %d\n", k, v)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true
	})
	return sb.String()
}

func (p *PrometheusLabelTable) nameIDsString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\nname                                                              nameId\n")
	sb.WriteString("--------------------------------------------------------------------------\n")
	p.labelNameIDs.Range(func(k string, v uint32) bool {
		row := fmt.Sprintf("%-64s  %d\n", k, v)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true
	})
	return sb.String()
}

func (p *PrometheusLabelTable) valueIDsString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\nvalue                                                                                                                             valueId\n")
	sb.WriteString("--------------------------------------------------------------------------------------------------------------------------------------------\n")
	p.labelValueIDs.Range(func(k string, v uint32) bool {
		row := fmt.Sprintf("%-128s  %d\n", k, v)
		if strings.Contains(row, filter) {
			sb.WriteString(row)
		}
		return true
	})
	return sb.String()
}

func (p *PrometheusLabelTable) columnIndexString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\ncolumnIndex  metricName                                                                                            metricId   name                                                              nameId\n")
	sb.WriteString("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")
	p.labelColumnIndexs.Range(func(k uint64, v uint32) bool {
		metricId := k >> METRICID_OFFSET
		nameId := k << (64 - METRICID_OFFSET) >> (64 - METRICID_OFFSET)
		metricName, name := "", ""
		p.metricNameIDs.Range(func(n string, i uint32) bool {
			if i == uint32(metricId) {
				metricName = n
				return false
			}
			return true
		})
		p.labelNameIDs.Range(func(n string, i uint32) bool {
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

func (p *PrometheusLabelTable) targetString(filter string) string {
	sb := &strings.Builder{}
	sb.WriteString("\ntargetId     job                                                              jobId    instance                          instanceId\n")
	sb.WriteString("---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

	p.targetIDs.Range(func(k uint64, v uint32) bool {
		jobId := k >> 32
		instanceId := k << (64 - JOBID_OFFSET) >> (64 - JOBID_OFFSET)
		job, instance := "", ""
		p.labelValueIDs.Range(func(n string, i uint32) bool {
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
		row := fmt.Sprintf("%-10d   %-64s  %-5d   %-32s     %d\n", v, job, jobId, instance, instanceId)
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

func (p *PrometheusLabelTable) statsString() string {
	sb := &strings.Builder{}
	sb.WriteString("\ntableType  total-count  max-id\n")
	sb.WriteString("--------------------------------\n")
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "metric", p.metricNameIDs.Len(), getStringMapMaxValue(p.metricNameIDs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "name", p.labelNameIDs.Len(), getStringMapMaxValue(p.labelNameIDs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "value", p.labelValueIDs.Len(), getStringMapMaxValue(p.labelValueIDs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "column", p.labelColumnIndexs.Len(), getUInt64MapMaxValue(p.labelColumnIndexs)))
	sb.WriteString(fmt.Sprintf("%-9s  %-11d  %-6d\n", "target", p.targetIDs.Len(), getUInt64MapMaxValue(p.targetIDs)))
	return sb.String()
}

func (p *PrometheusLabelTable) HandleSimpleCommand(op uint16, arg string) string {
	cmd := labelCmds[op]
	switch cmd {
	case "metric":
		return p.metricIDsString(arg)
	case "name":
		return p.nameIDsString(arg)
	case "value":
		return p.valueIDsString(arg)
	case "column":
		return p.columnIndexString(arg)
	case "target":
		return p.targetString(arg)
	case "stats":
		return p.statsString()
	case "test":
		return p.testString(arg)
	case "explain":
		return p.explainString(arg)
	}
	return p.statsString()
}

// request string as: metric=xxx,job=xxx,instance=xxx,label1=xxx,label2=xxx
func (p *PrometheusLabelTable) testString(request string) string {
	req := &trident.PrometheusLabelIDsRequest{}
	metricReq := &trident.MetricLabelRequest{}
	keyValues := strings.Split(request, ",")
	for _, kv := range keyValues {
		kv := strings.Split(kv, "=")
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "metric" {
			metricReq.MetricName = &(kv[1])
		} else {
			addLabel(metricReq, kv[0], kv[1])
		}
	}
	req.RequestLabels = append(req.RequestLabels, metricReq)
	resp, err := p.RequesteLabelIDs(req)
	if err != nil {
		return fmt.Sprintf("request: %s\nresponse failed: %s", req, err)
	}
	return fmt.Sprintf("request: %s\nresponse: %s", req, resp)
}

// explain string as: xxx|xxx|xxxx|xxxx|...,   means: metric_id|target_id|app_label_value_id_1|app_label_value_id_2|...
func (p *PrometheusLabelTable) explainString(str string) string {
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
	p.metricNameIDs.Range(func(n string, i uint32) bool {
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
	p.targetIDs.Range(func(k uint64, v uint32) bool {
		if v != targetId {
			return true
		}
		jobId := k >> 32
		instanceId := k << (64 - JOBID_OFFSET) >> (64 - JOBID_OFFSET)
		job, instance := "", ""
		p.labelValueIDs.Range(func(n string, i uint32) bool {
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

	names, values := []string{}, []string{}

	for i, valueId := range intValues[2:] {
		p.labelColumnIndexs.Range(func(k uint64, v uint32) bool {
			mid := k >> METRICID_OFFSET
			if uint64(metricId) != mid {
				return true
			}
			if v == uint32(i+1) {
				nameId := k << (64 - METRICID_OFFSET) >> (64 - METRICID_OFFSET)
				name, value := "", ""
				p.labelNameIDs.Range(func(n string, i uint32) bool {
					if i == uint32(nameId) {
						name = n
						return false
					}
					return true
				})
				p.labelValueIDs.Range(func(n string, i uint32) bool {
					if i == uint32(valueId) {
						value = n
						return false
					}
					return true
				})
				names = append(names, name)
				values = append(values, value)
				return false
			}
			return true
		})

	}

	explainedStr += fmt.Sprintf("metric=%s,job=%s,instance=%s", metricName, job, instance)
	for i := range names {
		explainedStr += fmt.Sprintf("%s=%s,", names[i], values[i])
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

	return debug.ClientRegisterSimple(CMD_PROMETHEUS_LABEL,
		debug.CmdHelper{
			Cmd:    "label",
			Helper: "show prometheus label info",
		},
		operates,
	)
}
