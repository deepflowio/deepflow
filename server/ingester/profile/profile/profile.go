package profile

import (
	"strconv"
	"time"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/profile/config"
	"github.com/deepflowio/deepflow/server/ingester/profile/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/profile/decoder"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

type Profile struct {
	Profiler *Profiler
}

type Profiler struct {
	Decoders      []*decoder.Decoder
	PlatformDatas []*grpc.PlatformInfoTable
	ProfileWriter *dbwriter.ProfileWriter
}

func NewProfile(config *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*Profile, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_EXTMETRICS_QUEUE)
	profileWriter, err := dbwriter.NewProfileWriter(datatype.MESSAGE_TYPE_PROFILE, config)
	if err != nil {
		return nil, err
	}
	profiler, err := NewProfiler(datatype.MESSAGE_TYPE_PROFILE, config, platformDataManager, manager, recv, profileWriter)
	if err != nil {
		return nil, err
	}
	return &Profile{
		Profiler: profiler,
	}, nil
}

func NewProfiler(msgType datatype.MessageType, config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, profileWriter *dbwriter.ProfileWriter) (*Profiler, error) {
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+msgType.String(),
		config.DecoderQueueSize,
		config.DecoderQueueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(msgType, decodeQueues, config.DecoderQueueCount)
	decoders := make([]*decoder.Decoder, config.DecoderQueueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, config.DecoderQueueCount)
	for i := 0; i < config.DecoderQueueCount; i++ {
		if platformDataManager != nil {
			var err error
			platformDatas[i], err = platformDataManager.NewPlatformInfoTable(false, "profile-"+msgType.String()+"-"+strconv.Itoa(i))
			if err != nil {
				return nil, err
			}
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			profileWriter,
		)
	}
	return &Profiler{
		Decoders:      decoders,
		PlatformDatas: platformDatas,
		ProfileWriter: profileWriter,
	}, nil
}

func (p *Profiler) Start() {
	for _, platformData := range p.PlatformDatas {
		if platformData != nil {
			platformData.Start()
		}
	}

	for _, decoder := range p.Decoders {
		go decoder.Run()
	}
}

func (p *Profiler) Close() {
	for _, platformData := range p.PlatformDatas {
		if platformData != nil {
			platformData.ClosePlatformInfoTable()
		}
	}

	for _, decoder := range p.Decoders {
		decoder.Close()
	}
}

func (p *Profile) Start() {
	p.Profiler.Start()
}

func (p *Profile) Close() error {
	p.Profiler.Close()
	return nil
}
