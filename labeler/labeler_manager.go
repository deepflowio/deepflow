package labeler

import (
	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/handler"
)

var log = logging.MustGetLogger("labeler")

type LabelerManager struct {
	policyTable *policy.PolicyTable
	readQueue   queue.QueueReader
	appQueue    []queue.QueueWriter
	running     bool
}

func NewLabelerManager(readQueue queue.QueueReader, appQueue ...queue.QueueWriter) *LabelerManager {
	return &LabelerManager{
		policyTable: policy.NewPolicyTable(policy.ACTION_FLOW_STAT),
		readQueue:   readQueue,
		appQueue:    appQueue,
	}
}

func (l *LabelerManager) OnPlatformDataChange(data []*policy.PlatformData) {
	l.policyTable.UpdateInterfaceData(data)
}

func (l *LabelerManager) OnServiceDataChange(data []*policy.ServiceData) {
	l.policyTable.UpdateServiceData(data)
}

func (l *LabelerManager) GetData(key *policy.LookupKey) {
	data, _ := l.policyTable.LookupAllByKey(key)
	if data != nil {
		log.Debug("QUERY KEY:", key, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}
}

func (l *LabelerManager) GetPolicy(packet *handler.MetaPacket) {
	key := &policy.LookupKey{
		SrcMac:      Mac2Uint64(packet.MacSrc),
		DstMac:      Mac2Uint64(packet.MacDst),
		SrcIp:       packet.IpSrc,
		DstIp:       packet.IpDst,
		Vlan:        packet.Vlan,
		Proto:       uint8(packet.Proto),
		Ttl:         packet.TTL,
		RxInterface: packet.InPort,
	}

	data, policy := l.policyTable.LookupAllByKey(key)
	if data != nil {
		packet.EndpointData = data
		log.Debug("QUERY PACKET:", packet, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}

	if policy != nil {
		log.Debug("POLICY", policy)
	}
}

func (l *LabelerManager) run() {
	for l.running {
		packet := l.readQueue.Get().(*handler.MetaPacket)
		l.GetPolicy(packet)

		for _, queue := range l.appQueue {
			queue.Put(packet)
		}
	}

	log.Info("Labeler manager exit")
}

func (l *LabelerManager) Start() {
	if !l.running {
		l.running = true
		log.Info("Start labeler manager")
		go l.run()
	}
}

func (l *LabelerManager) Stop(wait bool) {
	if l.running {
		log.Info("Stop labeler manager")
		l.running = false
	}
}
