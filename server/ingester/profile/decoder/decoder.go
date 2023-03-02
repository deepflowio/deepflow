package decoder

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/profile/dbwriter"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/deepflowio/deepflow/server/libs/zerodoc/pb"
	"github.com/op/go-logging"
	"github.com/pyroscope-io/pyroscope/pkg/convert/jfr"
	"github.com/pyroscope-io/pyroscope/pkg/convert/pprof"
	"github.com/pyroscope-io/pyroscope/pkg/ingestion"
	"github.com/pyroscope-io/pyroscope/pkg/storage/metadata"
	"github.com/pyroscope-io/pyroscope/pkg/storage/segment"
)

var log = logging.MustGetLogger("profile.decoder")

const (
	BUFFER_SIZE = 1024
)

var InProcessCounter uint32

type Counter struct {
	RawCount           int64 `statsd:"raw-count"`
	JavaProfileCount   int64 `statsd:"java-profile-count"`
	GolangProfileCount int64 `statsd:"golang-profile-count"`

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
}

type Decoder struct {
	index         int
	msgType       datatype.MessageType
	platformData  *grpc.PlatformInfoTable
	inQueue       queue.QueueReader
	profileWriter *dbwriter.ProfileWriter

	counter *Counter
	utils.Closable
}

func NewDecoder(index int, msgType datatype.MessageType,
	platformData *grpc.PlatformInfoTable,
	inQueue queue.QueueReader,
	profileWriter *dbwriter.ProfileWriter) *Decoder {
	return &Decoder{
		index:         index,
		msgType:       msgType,
		platformData:  platformData,
		inQueue:       inQueue,
		profileWriter: profileWriter,
		counter:       &Counter{},
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
		"msg_type": d.msgType.String()})
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
		if decoder.Failed() {
			log.Errorf("profile data decode failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
			return
		}

		parser := &Parser{
			vtapID:       vtapID,
			inTimestamp:  time.Now(),
			callBack:     d.profileWriter.Write,
			platformData: d.platformData,
			IP:           make([]byte, len(profile.Ip)),
		}
		copy(parser.IP, profile.Ip[:len(profile.Ip)])

		switch profile.Format {
		case "jfr":
			atomic.AddInt64(&d.counter.JavaProfileCount, 1)
			metadata := d.buildMetaData(profile)
			parser.profileName = metadata.Key.AppName()
			err := d.sendProfileData(&jfr.RawProfile{
				FormDataContentType: string(profile.ContentType),
				RawData:             profile.Data,
			}, profile.Format, parser, metadata)

			if err != nil {
				log.Errorf("decode java profile data failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
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
				log.Errorf("decode golang profile data failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
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
					log.Errorf("decode golang profile data failed, offset=%d len=%d", decoder.Offset(), len(decoder.Bytes()))
					return
				}
			}
		case "speedscope", "tree", "trie", "lines":
			// not implemented
			continue
		}
	}
}

func (d *Decoder) buildMetaData(profile *pb.Profile) ingestion.Metadata {
	profileName, err := url.QueryUnescape(profile.Name)
	if err != nil {
		log.Warning("decode profile.name wrong, got %s, will use as profilename", profile.Name)
		profileName = profile.Name
	}
	labels, err := segment.ParseKey(profileName)
	if err != nil {
		// 如果无法识别应用名称，直接使用 profile.Name 作为 app_service
		// if recognise application name failed, use profile.Name as app_service
		labels = &segment.Key{}
		labels.Add("__name__", profileName)
		log.Warning("parse profile labels wrong, got %s", profileName)
	}
	return ingestion.Metadata{
		StartTime:       time.Unix(int64(profile.From), 0),
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
