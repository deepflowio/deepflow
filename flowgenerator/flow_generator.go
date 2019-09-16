package flowgenerator

import (
	"math/rand"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
	. "gitlab.x.lan/yunshan/droplet-libs/queue"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
)

var log = logging.MustGetLogger("flowgenerator")

// hash of the key L3, symmetric
func getKeyL3Hash(meta *MetaPacket, basis uint32) uint64 {
	ipSrc := uint64(meta.IpSrc)
	ipDst := uint64(meta.IpDst)
	if meta.EthType == layers.EthernetTypeIPv6 {
		ipSrc = uint64(GetIpHash(meta.Ip6Src))
		ipDst = uint64(GetIpHash(meta.Ip6Dst))
	}
	if ipSrc >= ipDst {
		return ipSrc<<32 | ipDst
	}
	return ipDst<<32 | ipSrc
}

// hash of the key L4, symmetric
func getKeyL4Hash(meta *MetaPacket, basis uint32) uint64 {
	portSrc := uint32(meta.PortSrc)
	portDst := uint32(meta.PortDst)
	if portSrc >= portDst {
		return uint64(hashAdd(basis, (portSrc<<16)|portDst))
	}
	return uint64(hashAdd(basis, (portDst<<16)|portSrc))
}

func (f *FlowGenerator) getQuinTupleHash(meta *MetaPacket) uint64 {
	return getKeyL3Hash(meta, f.hashBasis) ^ ((uint64(meta.InPort) << 32) | getKeyL4Hash(meta, f.hashBasis))
}

func (m *FlowGenerator) getEthOthersQuinTupleHash(meta *MetaPacket) uint64 {
	return meta.MacSrc ^ meta.MacDst
}

func (f *FlowGenerator) processPackets(processBuffer []interface{}) {
	for i, e := range processBuffer {
		if e == nil { // flush indicator
			f.flowMap.InjectFlushTicker(toTimestamp(time.Now()))
			continue
		}

		meta := e.(*MetaPacket)
		hash := uint64(0)
		if meta.EthType != layers.EthernetTypeIPv4 && meta.EthType != layers.EthernetTypeIPv6 {
			hash = f.getEthOthersQuinTupleHash(meta)
		} else {
			hash = f.getQuinTupleHash(meta)
		}
		f.flowMap.InjectMetaPacket(hash, meta)

		ReleaseMetaPacket(meta)
		processBuffer[i] = nil
	}
}

func (f *FlowGenerator) handlePackets() {
	inputQueue := f.inputQueue
	recvBuffer := make([]interface{}, QUEUE_BATCH_SIZE)
	gotSize := 0

	for f.running {
		gotSize = inputQueue.Gets(recvBuffer)
		f.processPackets(recvBuffer[:gotSize])
	}
}

func (f *FlowGenerator) Start() {
	if !f.running {
		f.running = true
		go f.handlePackets()
	}
	log.Infof("flow generator %d started", f.index)
}

func (f *FlowGenerator) Stop() {
	if f.running {
		f.running = false
	}
	log.Infof("flow generator %d stopped", f.index)
}

// create a new flow generator
func New(inputQueue QueueReader, packetAppQueue, flowAppQueue QueueWriter, flowLimitNum, index int, flushInterval time.Duration) *FlowGenerator {
	flowGenerator := &FlowGenerator{
		hashBasis:  rand.Uint32(),
		flowMap:    NewFlowMap(int(hashMapSize), flowLimitNum, index, maxTimeout, reportTolerance, flushInterval, packetAppQueue, flowAppQueue),
		inputQueue: inputQueue,
		index:      index,
	}
	return flowGenerator
}
