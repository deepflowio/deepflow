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

package decoder

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/profile/common"
	"github.com/deepflowio/deepflow/server/ingester/profile/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/klauspost/compress/zstd"
	"github.com/pyroscope-io/pyroscope/pkg/storage"
)

const (
	// the maximum duration of off-cpu profile is 1h + <1s
	MAX_OFF_CPU_PROFILE_SPLIT_COUNT = 4000
	DEFAULT_COMPRESSION_ALGO        = "zstd"
)

type Parser struct {
	profileName   string
	vtapID        uint16
	orgId, teamId uint16
	IP            net.IP
	podID         uint32

	// profileWriter.Write
	profileWriterCallback       func([]interface{})
	appServiceTagWriterCallback func(*dbwriter.InProcessProfile)
	offCpuSplittingGranularity  int

	platformData    *grpc.PlatformInfoTable
	inTimestamp     time.Time
	compressionAlgo string
	*observer
	*processTracer
	*Counter
}

type processTracer struct {
	pid       uint32
	stime     int64
	eventType string
	value     uint64
}

// implement storage.Putter
// triggered by input.Profile.Parse
func (p *Parser) Put(ctx context.Context, i *storage.PutInput) error {
	// for application profiling, appName like : application.cpu, e.g.:<appName>.<eventType>
	eventType := strings.TrimPrefix(i.Key.AppName(), fmt.Sprintf("%s.", p.profileName))
	if p.processTracer != nil {
		// for ebpf profiling event type
		eventType = p.processTracer.eventType
	}
	log.Debugf("put profile data, from: %d, spy: %s, event type: %s", i.StartTime.Unix(), i.SpyName, eventType)
	i.Val.IterateStacks(func(name string, self uint64, stack []string) {
		for i, j := 0, len(stack)-1; i < j; i, j = i+1, j-1 {
			stack[i], stack[j] = stack[j], stack[i]
		}
		onelineStack := strings.Join(stack, ";")
		atomic.AddInt64(&p.Counter.UncompressSize, int64(len(stack)))
		location := compress([]byte(onelineStack), p.compressionAlgo)
		atomic.AddInt64(&p.Counter.CompressedSize, int64(len(location)))

		inProcesses := p.stackToInProcess(location, self, i.StartTime, i.Units.String(), eventType, i.SpyName, i.Key.Labels())
		// in the same batch, app_service is the same and only needs to be written once.
		p.appServiceTagWriterCallback(inProcesses[0].(*dbwriter.InProcessProfile))
		p.profileWriterCallback(inProcesses)
	})
	return nil
}

// implement storage.MetricsExporter
// triggered by input.Profile.Parse
func (p *Parser) Evaluate(i *storage.PutInput) (storage.SampleObserver, bool) {
	return p.observer, true
}

// eBPF profiling direct write into db
func (p *Parser) rawStackToInProcess(stack []byte, value uint64, startTime time.Time, units, spyName string, labels map[string]string, srcCompressed bool) error {
	data := string(stack)
	// sender require compress, but ingester require not compress, should decompress
	if srcCompressed && p.compressionAlgo == "" {
		data = deCompress(stack, DEFAULT_COMPRESSION_ALGO)
	}
	// sender require not compress, but ingester require compress, should compress
	if !srcCompressed && p.compressionAlgo == DEFAULT_COMPRESSION_ALGO {
		data = compress(stack, p.compressionAlgo)
	}
	if len(data) == 0 {
		return fmt.Errorf("stack parsing failed, startTime: %d, spy: %s", startTime.Unix(), spyName)
	}
	// otherwise, do nothing, directly write into db
	inProcess := p.stackToInProcess(data, value, startTime, units, p.processTracer.eventType, spyName, labels)
	p.appServiceTagWriterCallback(inProcess[0].(*dbwriter.InProcessProfile))
	p.profileWriterCallback(inProcess)
	return nil
}

func (p *Parser) stackToInProcess(location string, value uint64, startTime time.Time, units, eventType, spyName string, labels map[string]string) []interface{} {
	tagNames := make([]string, 0, len(labels))
	tagValues := make([]string, 0, len(labels))
	for k, v := range labels {
		tagNames = append(tagNames, k)
		tagValues = append(tagValues, v)
	}
	ret := dbwriter.AcquireInProcess()
	var ip4 uint32
	if ip := p.IP.To4(); ip != nil {
		ip4 = utils.IpToUint32(ip)
		ret.IsIPv4 = true
	}
	if ret.IsIPv4 {
		ret.IP4 = ip4
	} else {
		ret.IP6 = p.IP
	}

	var pid uint32
	var stime int64

	profileValueUs := int64(value)
	if p.processTracer != nil {
		// only for eBPF profiling
		profileValueUs = int64(p.value)
		pid = p.processTracer.pid
		stime = p.processTracer.stime
	}

	ret.FillProfile(startTime,
		units,
		labels,
		p.platformData,
		p.vtapID,
		p.orgId, p.teamId,
		p.podID,
		p.profileName,
		eventType,
		location,
		p.compressionAlgo,
		profileValueUs,
		p.inTimestamp,
		spyMap[spyName],
		pid,
		stime,
		tagNames,
		tagValues)

	var writeItems []interface{}
	granularityUs := int64(p.offCpuSplittingGranularity) * int64(time.Second/time.Microsecond)
	// each off-cpu profile data represents the function call stack within a long period of time (perhaps up to one hour).
	// It is inappropriate to use a single end_time to express a period of time.
	if ret.ProfileEventType == eBPFEventType[pb.ProfileEventType_EbpfOffCpu] {
		if p.offCpuSplittingGranularity > 0 &&
			profileValueUs > granularityUs {

			splitCount := (profileValueUs + granularityUs - 1) / granularityUs
			// prevent abnormal data from causing excessive writing
			if splitCount > MAX_OFF_CPU_PROFILE_SPLIT_COUNT {
				splitCount = MAX_OFF_CPU_PROFILE_SPLIT_COUNT
			}

			writeItems = make([]interface{}, 0, splitCount)
			for i := int64(0); i < splitCount-1; i++ {
				splitItem := ret.Clone()
				// the time for data reporting is the end_time
				splitItem.Time = splitItem.Time - uint32(i)*uint32(p.offCpuSplittingGranularity)
				splitItem.ProfileCreateTimestamp = splitItem.ProfileCreateTimestamp - i*granularityUs
				splitItem.ProfileValue = granularityUs
				writeItems = append(writeItems, splitItem)
			}
			atomic.AddInt64(&p.Counter.OffCpuSplitCount, 1)
			atomic.AddInt64(&p.Counter.OffCpuSplitIntoCount, int64(splitCount))

			// set last split item from ret itself
			ret.Time = ret.Time - uint32(splitCount-1)*uint32(p.offCpuSplittingGranularity)
			ret.ProfileCreateTimestamp = ret.ProfileCreateTimestamp - (splitCount-1)*granularityUs
			ret.ProfileValue = profileValueUs - (splitCount-1)*granularityUs
		} else {
			atomic.AddInt64(&p.Counter.OffCputNotSplitCount, 1)
		}
	}
	writeItems = append(writeItems, ret)

	return writeItems
}

type observer struct {
	// FIXME: not implemented, used it for `func.Evaluate`
}

func (s *observer) Observe(k []byte, v int) {
	// FIXME: generate some metrics
	// e.g.: convert profile application & profile labels to prometheus series
}

func compress(src []byte, algo string) string {
	switch algo {
	case "":
		return string(src)
	case DEFAULT_COMPRESSION_ALGO:
		dst := make([]byte, 0, len(src))
		result, err := common.ZstdCompress(dst, src, zstd.SpeedDefault)
		if err != nil {
			log.Errorf("compress error: %v", err)
			return string(src)
		}
		// str after compressed and algo
		return string(result)
	default:
		return string(src)
	}
}

func deCompress(str []byte, algo string) string {
	switch algo {
	case "":
		return string(str)
	case DEFAULT_COMPRESSION_ALGO:
		dst := make([]byte, 0, len(str))
		result, err := common.ZstdDecompress(dst, str)
		if err != nil {
			log.Errorf("decompress error: %v", err)
			return ""
		}
		return string(result)
	default:
		return string(str)
	}
}
