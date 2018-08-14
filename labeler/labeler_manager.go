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
	labeler := &LabelerManager{
		policyTable: policy.NewPolicyTable(policy.ACTION_FLOW_STAT),
		readQueue:   readQueue,
		appQueue:    appQueue,
	}

	ips := make([]net.IP, len(cfg.ControllerIps))
	for i, ipString := range cfg.ControllerIps {
		ips[i] = net.ParseIP(ipString)
	}
	initiator := rpc.NewGRpcInitiator(ips, cfg.ControllerPort, 10*time.Second)
	rpcHandle := []rpc.RpcHandle{labeler}
	rpcWorker := rpc.NewRpcWorker(&initiator, rpcHandle)
	labeler.rpcWorker = rpcWorker

	return labeler
}

func (l *LabelerManager) NewPlatformData(vifData *protobuf.Interface) *policy.PlatformData {
	macInt := uint64(0)
	if mac, err := net.ParseMAC(vifData.GetMac()); err == nil {
		macInt = utils.Mac2Uint64(mac)
	}

	hostIp := uint32(0)
	ip := net.ParseIP(vifData.GetLaunchServer())
	if ip != nil {
		hostIp = ip2uint(ip)
	}

	var ips []*policy.IpNet
	for _, ipData := range vifData.IpResources {
		fixIp := net.ParseIP(ipData.GetIp())
		if fixIp == nil {
			continue
		}
		netmask := ipData.GetMasklen()
		if netmask == 0 || netmask > policy.MAX_MASK_LEN || netmask < policy.MIN_MASK_LEN {
			netmask = policy.MAX_MASK_LEN
		}
		var ipInfo = &policy.IpNet{
			Ip:       ip2uint(fixIp),
			Netmask:  netmask,
			SubnetId: ipData.GetSubnetId(),
		}
		ips = append(ips, ipInfo)
	}
	return &policy.PlatformData{
		Mac:        macInt,
		Ips:        ips,
		EpcId:      int32(vifData.GetEpcId()),
		DeviceType: vifData.GetDeviceType(),
		DeviceId:   vifData.GetDeviceId(),
		IfIndex:    vifData.GetIfIndex(),
		IfType:     vifData.GetIfType(),
		HostIp:     hostIp,
		GroupIds:   vifData.GetGroupIds(),
	}
}

func (l *LabelerManager) NewServiceData(service *protobuf.Service) *policy.ServiceData {
	if service == nil {
		return nil
	}
	portsStr := service.GetPorts()
	var ports []uint32
	splitedPorts := strings.Split(portsStr, ",")
	for _, port := range splitedPorts {
		portInt, err := strconv.Atoi(port)
		if err != nil {
			ports = append(ports, uint32(portInt))
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
	var serviceDatas []*policy.ServiceData
	for _, service := range services {
		if newData := l.NewServiceData(service); newData != nil {
			serviceDatas = append(serviceDatas, newData)
		}
	}
	return serviceDatas
}

func (l *LabelerManager) Convert2PlatformData(interfaces []*protobuf.Interface) []*policy.PlatformData {
	var platformDatas []*policy.PlatformData
	for _, data := range interfaces {
		if newData := l.NewPlatformData(data); newData != nil {
			platformDatas = append(platformDatas, newData)
		}
	}
	return platformDatas
}

func (l *LabelerManager) RpcHandle(response *protobuf.SyncResponse) {
	log.Debug(*response)
	pfdata := response.GetPlatformData()
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

func (l *LabelerManager) GetPolicy(packet *handler.MetaPacketHeader) {
	key := &policy.LookupKey{
		SrcMac:      utils.Mac2Uint64(packet.MacSrc),
		DstMac:      utils.Mac2Uint64(packet.MacDst),
		SrcIp:       ip2uint(packet.IpSrc),
		DstIp:       ip2uint(packet.IpSrc),
		Vlan:        packet.Vlan,
		Proto:       uint8(packet.Proto),
		Ttl:         packet.TTL,
		RxInterface: packet.InPort,
	}

	data, policy := l.policyTable.LookupAllByKey(key)
	if data != nil {
		packet.EndPointData = data
		log.Debug("QUERY PACKET:", packet, "SRC:", data.SrcInfo, "DST:", data.DstInfo)
	}

	if policy != nil {
		log.Debug("POLICY", policy)
	}
}

func (l *LabelerManager) run() {
	for l.running {
		packet := l.readQueue.Get().(*handler.MetaPacketHeader)
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
		l.rpcWorker.Start()
		go l.run()
	}
}

func (l *LabelerManager) Stop(wait bool) {
	if l.running {
		log.Info("Stop labeler manager")
		l.running = false
	}
}
