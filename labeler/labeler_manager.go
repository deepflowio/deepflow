package labeler

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/policy"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/utils"

	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/handler"
	"gitlab.x.lan/yunshan/droplet/protobuf"
	"gitlab.x.lan/yunshan/droplet/rpc"
)

var log = logging.MustGetLogger("labeler")

type LabelerManager struct {
	policyTable *policy.PolicyTable
	readQueue   queue.QueueReader
	appQueue    []queue.QueueWriter
	rpcWorker   *rpc.RpcWorker
	running     bool
}

func NewLabelerManager(cfg config.Config, readQueue queue.QueueReader, appQueue ...queue.QueueWriter) *LabelerManager {
	lber := &LabelerManager{
		policyTable: policy.NewPolicyTable(policy.ACTION_FLOW_STAT),
		readQueue:   readQueue,
		appQueue:    appQueue,
	}

	ctrips := make([]net.IP, len(cfg.ControllerIps))
	for i, ipString := range cfg.ControllerIps {
		ctrips[i] = net.ParseIP(ipString)
	}
	initiator := rpc.NewGRpcInitiator(ctrips, cfg.ControllerPort, 10*time.Second)
	rpchandle := []rpc.RpcHandle{lber}
	rpcworker := rpc.NewRpcWorker(&initiator, rpchandle)
	lber.rpcWorker = rpcworker

	return lber
}

func (l *LabelerManager) NewPlatformData(vifdata *protobuf.Interface) *policy.PlatformData {
	macint := uint64(0)
	if mac, err := net.ParseMAC(vifdata.GetMac()); err == nil {
		macint = utils.Mac2Uint64(mac)
	}

	hostip := uint32(0)
	ip := net.ParseIP(vifdata.GetLaunchServer())
	if ip != nil {
		hostip = ip2uint(ip)
	}

	var ips []*policy.IpNet
	for _, ipdata := range vifdata.IpResources {
		fixip := net.ParseIP(ipdata.GetIp())
		if fixip == nil {
			continue
		}
		netmask := ipdata.GetMasklen()
		if netmask == 0 || netmask > policy.MAX_MASK_LEN || netmask < policy.MIN_MASK_LEN {
			netmask = policy.MAX_MASK_LEN
		}
		var ipinfo = &policy.IpNet{
			Ip:       ip2uint(fixip),
			Netmask:  netmask,
			SubnetId: ipdata.GetSubnetId(),
		}
		ips = append(ips, ipinfo)
	}
	return &policy.PlatformData{
		Mac:        macint,
		Ips:        ips,
		EpcId:      int32(vifdata.GetEpcId()),
		DeviceType: vifdata.GetDeviceType(),
		DeviceId:   vifdata.GetDeviceId(),
		IfIndex:    vifdata.GetIfIndex(),
		IfType:     vifdata.GetIfType(),
		HostIp:     hostip,
		GroupIds:   vifdata.GetGroupIds(),
	}
}

func (l *LabelerManager) NewServicedata(service *protobuf.Service) *policy.ServiceData {
	if service == nil {
		return nil
	}
	strports := service.GetPorts()
	var ports []uint32
	splitports := strings.Split(strports, ",")
	for _, port := range splitports {
		intport, err := strconv.Atoi(port)
		if err != nil {
			ports = append(ports, uint32(intport))
		}
	}

	return &policy.ServiceData{
		Id:      service.GetId(),
		GroupId: service.GetGroupId(),
		Proto:   uint16(service.GetProtocol()),
		Ports:   ports,
	}
}

func (l *LabelerManager) Convert2ServiceData(services []*protobuf.Service) []*policy.ServiceData {
	var servicedatas []*policy.ServiceData
	for _, service := range services {
		if newdata := l.NewServicedata(service); newdata != nil {
			servicedatas = append(servicedatas, newdata)
		}
	}
	return servicedatas
}

func (l *LabelerManager) Convert2PlatformData(interfaces []*protobuf.Interface) []*policy.PlatformData {
	var pfdatas []*policy.PlatformData
	for _, data := range interfaces {
		if newdata := l.NewPlatformData(data); newdata != nil {
			pfdatas = append(pfdatas, newdata)
		}
	}
	return pfdatas
}

func (l *LabelerManager) RpcHandle(res *protobuf.SyncResponse) {
	log.Debug(*res)
	pfdata := res.GetPlatformData()
	if pfdata != nil {
		if interfaces := pfdata.GetInterfaces(); interfaces != nil {
			data := l.Convert2PlatformData(interfaces)
			l.policyTable.UpdateInterfaceData(data)
		} else {
			log.Warning("interfaces is nil")
		}
		if services := pfdata.GetServices(); services != nil {
			data := l.Convert2ServiceData(services)
			l.policyTable.UpdateServiceData(data)
		}
	}
}

func ip2uint(ip net.IP) uint32 {
	if len(ip) == 0 {
		return 0
	}
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func (l *LabelerManager) GetData(key *policy.LookupKey) {
	data, _ := l.policyTable.LookupAllByKey(key)
	if data != nil {
		log.Debug("QUERY KEY:", key, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}
}

func (l *LabelerManager) GetPolicy(pkt *handler.MetaPacketHeader) {
	key := &policy.LookupKey{
		SrcMac:      utils.Mac2Uint64(pkt.MacSrc),
		DstMac:      utils.Mac2Uint64(pkt.MacDst),
		SrcIp:       ip2uint(pkt.IpSrc),
		DstIp:       ip2uint(pkt.IpSrc),
		Vlan:        pkt.Vlan,
		Proto:       uint8(pkt.Proto),
		Ttl:         pkt.TTL,
		RxInterface: pkt.InPort,
	}

	data, policy := l.policyTable.LookupAllByKey(key)
	if data != nil {
		pkt.EpData = data
		log.Debug("QUERY PKT:", pkt, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}

	if policy != nil {
		log.Debug("POLICY", policy)
	}
}

func (l *LabelerManager) run() {
	for l.running {
		pkt := l.readQueue.Get().(*handler.MetaPacketHeader)
		l.GetPolicy(pkt)

		for _, queue := range l.appQueue {
			queue.Put(pkt)
		}
	}

	log.Info("Label Manager Exit")
}

func (l *LabelerManager) Start() {
	if !l.running {
		l.running = true
		log.Info("Start Label Manager")
		l.rpcWorker.Start()
		go l.run()
	}
}

func (l *LabelerManager) Stop(wait bool) {
	if l.running {
		log.Info("Stop trident adapt")
		l.running = false
	}
}
