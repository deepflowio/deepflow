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
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	profile_common "github.com/deepflowio/deepflow/server/ingester/profile/common"
	"github.com/deepflowio/deepflow/server/ingester/profile/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/google/uuid"
	logging "github.com/op/go-logging"
	"github.com/pyroscope-io/pyroscope/pkg/convert/jfr"
	"github.com/pyroscope-io/pyroscope/pkg/convert/pprof"
	pprofile "github.com/pyroscope-io/pyroscope/pkg/convert/profile"
	"github.com/pyroscope-io/pyroscope/pkg/ingestion"
	"github.com/pyroscope-io/pyroscope/pkg/storage/metadata"
	"github.com/pyroscope-io/pyroscope/pkg/storage/segment"
)

var log = logging.MustGetLogger("profile.decoder")

const (
	BUFFER_SIZE = 1024

	UNICODE_NULL = "\x00"
)

type Counter struct {
	RawCount           int64 `statsd:"raw-count"`
	JavaProfileCount   int64 `statsd:"java-profile-count"`
	GolangProfileCount int64 `statsd:"golang-profile-count"`
	EBPFProfileCount   int64 `statsd:"EBPF-profile-count"`

	UncompressSize int64 `statsd:"uncompress-size"`
	CompressedSize int64 `statsd:"compressed-size"`

	TotalTime int64 `statsd:"total-time"`
	AvgTime   int64 `statsd:"avg-time"`
}

var spyMap = map[string]string{
	"gospy":     "Golang",
	"javaspy":   "Java",
	"pyspy":     "python",
	"rbspy":     "ruby",
	"phpspy":    "PHP",
	"dotnetspy": "dotnet",
	"nodespy":   "Node",
	"eBPF":      "eBPF",
}

var eBPFEventType = map[pb.ProfileEventType]string{
	pb.ProfileEventType_External:   "third-party",
	pb.ProfileEventType_EbpfOnCpu:  "on-cpu",
	pb.ProfileEventType_EbpfOffCpu: "off-cpu",
}

type Decoder struct {
	index           int
	msgType         datatype.MessageType
	platformData    *grpc.PlatformInfoTable
	inQueue         queue.QueueReader
	profileWriter   *dbwriter.ProfileWriter
	compressionAlgo string

	counter *Counter
	utils.Closable
}

func NewDecoder(index int, msgType datatype.MessageType, compressionAlgo string,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	profileWriter *dbwriter.ProfileWriter) *Decoder {
	return &Decoder{
		index:           index,
		msgType:         msgType,
		platformData:    platformData,
		inQueue:         inQueue,
		profileWriter:   profileWriter,
		compressionAlgo: compressionAlgo,
		counter:         &Counter{},
	}
}

func (d *Decoder) GetCounter() interface{} {
	var counter *Counter
	counter, d.counter = d.counter, &Counter{}
	if counter.RawCount > 0 {
		counter.AvgTime = counter.TotalTime / counter.RawCount
	}
	return counter
}

func (d *Decoder) Run() {
	common.RegisterCountableForIngester("decoder", d, stats.OptionStatTags{
		"thread":   strconv.Itoa(d.index),
		"msg_type": datatype.MESSAGE_TYPE_PROFILE.String()})
	buffer := make([]interface{}, BUFFER_SIZE)
	decoder := &codec.SimpleDecoder{}
	for {
		n := d.inQueue.Gets(buffer)
		start := time.Now()
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				continue
			}
			atomic.AddInt64(&d.counter.RawCount, 1)
			recvBytes, ok := buffer[i].(*receiver.RecvBuffer)
			if !ok {
				log.Warning("get decode queue data type wrong")
				continue
			}
			decoder.Init(recvBytes.Buffer[recvBytes.Begin:recvBytes.End])
			if d.msgType == datatype.MESSAGE_TYPE_PROFILE {
				d.handleProfileData(recvBytes.VtapID, decoder)
			}
			receiver.ReleaseRecvBuffer(recvBytes)
		}
		d.counter.TotalTime += int64(time.Since(start))
	}
}

func (d *Decoder) handleProfileData(vtapID uint16, decoder *codec.SimpleDecoder) {
	for !decoder.IsEnd() {
		profile := &pb.Profile{}
		decoder.ReadPB(profile)
		if decoder.Failed() || profile == nil {
			log.Errorf("profile data decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}

		parser := &Parser{
			vtapID:          vtapID,
			inTimestamp:     time.Now(),
			callBack:        d.profileWriter.Write,
			platformData:    d.platformData,
			IP:              make([]byte, len(profile.Ip)),
			podID:           profile.PodId,
			compressionAlgo: d.compressionAlgo,
			observer:        &observer{},
			Counter:         d.counter,
		}
		copy(parser.IP, profile.Ip[:len(profile.Ip)])

		switch profile.Format {
		case "jfr":
			atomic.AddInt64(&d.counter.JavaProfileCount, 1)
			metadata := d.buildMetaData(profile)
			parser.profileName = metadata.Key.AppName()
			decompressJfr, err := profile_common.GzipDecompress(profile.Data)
			if err != nil {
				log.Errorf("decompress java profile data failed, offset=%d, len=%d, err=%s", decoder.Offset(), len(decoder.Bytes()), err)
				return
			}
			err = d.sendProfileData(&jfr.RawProfile{
				FormDataContentType: string(profile.ContentType),
				RawData:             decompressJfr,
			}, profile.Format, parser, metadata)

			if err != nil {
				log.Errorf("decode java profile data failed, offset=%d, len=%d, err=%s", decoder.Offset(), len(decoder.Bytes()), err)
				return
			}
		case "pprof":
			atomic.AddInt64(&d.counter.GolangProfileCount, 1)
			metadata := d.buildMetaData(profile)
			parser.profileName = metadata.Key.AppName()
			err := d.sendProfileData(&pprof.RawProfile{
				FormDataContentType: string(profile.ContentType),
				RawData:             profile.Data,
			}, profile.Format, parser, metadata)
			if err != nil {
				log.Errorf("decode golang profile data failed, offset=%d, len=%d, err=%s", decoder.Offset(), len(decoder.Bytes()), err)
				return
			}
		case "":
			// 如果 format == "" && contentType 有 "multipart/form-data"，默认当作 pprof 来解析，且 StreamingParser&PoolStreamingParser = true
			// if format == "" && contentType has "multipart/form-data", using pprof parser as default, StreamingParser&PoolStreamingParser = true
			if strings.Contains(string(profile.ContentType), "multipart/form-data") {
				atomic.AddInt64(&d.counter.GolangProfileCount, 1)
				metadata := d.buildMetaData(profile)
				parser.profileName = metadata.Key.AppName()
				err := d.sendProfileData(&pprof.RawProfile{
					FormDataContentType: string(profile.ContentType),
					RawData:             profile.Data,
					StreamingParser:     true,
					PoolStreamingParser: true,
				}, profile.Format, parser, metadata)
				if err != nil {
					log.Errorf("decode golang profile data failed, offset=%d, len=%d, err=%s", decoder.Offset(), len(decoder.Bytes()), err)
					return
				}
			} else {
				atomic.AddInt64(&d.counter.EBPFProfileCount, 1)
				profile = d.filleBPFData(profile)
				metadata := d.buildMetaData(profile)
				parser.profileName = metadata.Key.AppName()
				parser.processTracer = &processTracer{value: profile.Count, pid: profile.Pid, stime: int64(profile.Stime), eventType: eBPFEventType[profile.EventType]}
				err := d.sendProfileData(&pprofile.RawProfile{
					Format:  ingestion.FormatLines,
					RawData: profile.Data,
				}, profile.Format, parser, metadata)
				if err != nil {
					log.Errorf("decode ebpf profile data failed, offset=%d, len=%d, err=%s", decoder.Offset(), len(decoder.Bytes()), err)
					return
				}
			}
		case "speedscope", "tree", "trie", "lines":
			// not implemented
			continue
		}
	}
}

func (d *Decoder) filleBPFData(profile *pb.Profile) *pb.Profile {
	profile.From = uint32(profile.Timestamp / 1e9) // ns to s
	profile.Until = uint32(time.Now().Unix())
	profile.Units = string(metadata.SamplesUnits)
	profile.AggregationType = string(metadata.SumAggregationType)
	profile.SpyName = "eBPF"
	return profile
}

func (d *Decoder) buildMetaData(profile *pb.Profile) ingestion.Metadata {
	var profileName string
	var err error
	if profile.Name == "" {
		if profile.ProcessName != "" {
			// if profile comes from eBPF, use processName as profileName
			profileName = strings.Trim(profile.ProcessName, UNICODE_NULL)
		} else {
			profileName = fmt.Sprintf("%s-%s", "profile-empty-service", generateUUID())
		}
	} else {
		profileName, err = url.QueryUnescape(profile.Name)
		if err != nil {
			log.Debugf("decode profile.name wrong, got %s, will use as profilename", profile.Name)
			profileName = profile.Name
		}
	}
	labels, err := segment.ParseKey(profileName)
	if err != nil {
		// 如果无法识别应用名称，直接使用 profileName 作为 app_service
		// if recognise application name failed, use profileName as app_service
		labelKey := make(map[string]string, 1)
		labels = segment.NewKey(labelKey)
		labels.Add("__name__", profileName)
	}
	// use app-profile with `from` params
	startTime := time.Unix(int64(profile.From), 0)
	// using ebpf-profile with `timestamp` nanoseconds parse
	if profile.Timestamp > 0 {
		startTime = time.Unix(0, int64(profile.Timestamp))
	}
	return ingestion.Metadata{
		StartTime:       startTime,
		EndTime:         time.Unix(int64(profile.Until), 0),
		SpyName:         profile.SpyName,
		Key:             labels,
		SampleRate:      profile.SampleRate,
		Units:           metadata.Units(profile.Units),
		AggregationType: metadata.AggregationType(profile.AggregationType),
	}
}

func (d *Decoder) sendProfileData(profile ingestion.RawProfile, format string, parser *Parser, metadata ingestion.Metadata) error {
	input := &ingestion.IngestInput{
		Format:   ingestion.Format(format),
		Profile:  profile,
		Metadata: metadata,
	}
	return input.Profile.Parse(context.TODO(), parser, parser, metadata)
}

// generate uuid with length 8
func generateUUID() string {
	return uuid.New().String()[:8]
}
