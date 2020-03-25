package grpc

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"gitlab.x.lan/yunshan/droplet-libs/utils"
	"gitlab.x.lan/yunshan/message/trident"
)

// 以最后一次NewPlatformInfoTable() table作为全局的platformInfoTable
var platformInfoTable *PlatformInfoTable = &PlatformInfoTable{lock: &sync.RWMutex{}}

const (
	DEFAULT_SYNC_INTERVAL = time.Minute
)

type EpcIDIPV6 struct {
	EpcID uint32
	IP    [net.IPv6len]byte
}

type Info struct {
	Host       uint32
	HostID     uint32
	RegionID   uint32
	DeviceType uint32
	DeviceID   uint32
	SubnetID   uint32
	PodNodeID  uint32
	AZID       uint32
}

type PlatformInfoTable struct {
	epcIDIPV4Infos map[uint64]*Info
	epcIDIPV6Infos map[EpcIDIPV6]*Info

	bootTime            uint32
	processName         string
	versionPlatformData uint64

	*GrpcSession
	lock *sync.RWMutex
}

func ClosePlatformInfoTable() {
	platformInfoTable.Close()
}

func QueryIPV4Infos(epcID int16, ipv4 uint32) *Info {
	return platformInfoTable.QueryIPV4Infos(epcID, ipv4)
}

func QueryIPV6Infos(epcID int16, ipv6 net.IP) *Info {
	return platformInfoTable.QueryIPV6Infos(epcID, ipv6)
}

func QueryIPV4InfosPair(epcID0 int16, ipv40 uint32, epcID1 int16, ipv41 uint32) (info0 *Info, info1 *Info) {
	return platformInfoTable.QueryIPV4InfosPair(epcID0, ipv40, epcID1, ipv41)
}

func QueryIPV6InfosPair(epcID0 int16, ipv60 net.IP, epcID1 int16, ipv61 net.IP) (info0 *Info, info1 *Info) {
	return platformInfoTable.QueryIPV6InfosPair(epcID0, ipv60, epcID1, ipv61)
}

func NewPlatformInfoTable(ips []net.IP, port int, processName string) *PlatformInfoTable {
	table := &PlatformInfoTable{
		bootTime:       uint32(time.Now().Unix()),
		GrpcSession:    &GrpcSession{},
		lock:           &sync.RWMutex{},
		epcIDIPV4Infos: make(map[uint64]*Info),
		epcIDIPV6Infos: make(map[EpcIDIPV6]*Info),
	}
	runOnce := func() {
		if err := table.Reload(); err != nil {
			log.Warning(err)
		}
	}
	table.Init(ips, uint16(port), DEFAULT_SYNC_INTERVAL, runOnce)
	platformInfoTable = table
	return table
}

func (t *PlatformInfoTable) QueryIPV4Infos(epcID int16, ipv4 uint32) *Info {
	if info, ok := t.epcIDIPV4Infos[uint64(epcID)<<32|uint64(ipv4)]; ok {
		return info
	}
	return nil
}

// 需要一起查询, 防止查询时，平台信息更新
func (t *PlatformInfoTable) QueryIPV4InfosPair(epcID0 int16, ipv40 uint32, epcID1 int16, ipv41 uint32) (info0 *Info, info1 *Info) {
	t.lock.RLock()
	if info, ok := t.epcIDIPV4Infos[uint64(epcID0)<<32|uint64(ipv40)]; ok {
		info0 = info
	}
	if info, ok := t.epcIDIPV4Infos[uint64(epcID1)<<32|uint64(ipv41)]; ok {
		info1 = info
	}
	t.lock.RUnlock()
	return
}

func (t *PlatformInfoTable) QueryIPV6Infos(epcID int16, ipv6 net.IP) *Info {
	epcIDIP := EpcIDIPV6{}
	epcIDIP.EpcID = uint32(epcID)
	copy(epcIDIP.IP[:], ipv6)

	if info, ok := t.epcIDIPV6Infos[epcIDIP]; ok {
		return info
	}
	return nil
}

func (t *PlatformInfoTable) QueryIPV6InfosPair(epcID0 int16, ipv60 net.IP, epcID1 int16, ipv61 net.IP) (info0 *Info, info1 *Info) {
	epcIDIP0, epcIDIP1 := EpcIDIPV6{}, EpcIDIPV6{}
	epcIDIP0.EpcID = uint32(epcID0)
	copy(epcIDIP0.IP[:], ipv60)
	epcIDIP1.EpcID = uint32(epcID1)
	copy(epcIDIP1.IP[:], ipv61)

	t.lock.RLock()
	if info, ok := t.epcIDIPV6Infos[epcIDIP0]; ok {
		info0 = info
	}
	if info, ok := t.epcIDIPV6Infos[epcIDIP1]; ok {
		info1 = info
	}
	t.lock.RUnlock()
	return
}

func (t *PlatformInfoTable) String() string {
	sb := &strings.Builder{}
	t.lock.RLock()

	if len(t.epcIDIPV4Infos) > 0 {
		sb.WriteString("\nepcid   ipv4              host            hostID  regionID  deviceType  deviceID    subnetID  podNodeID azID\n")
		sb.WriteString("-------------------------------------------------------------------------------------------------------------------\n")
	}
	epcIP4s := make([]uint64, 0)
	for epcIP, _ := range t.epcIDIPV4Infos {
		epcIP4s = append(epcIP4s, epcIP)
	}
	sort.Slice(epcIP4s, func(i, j int) bool {
		return epcIP4s[i] < epcIP4s[j]
	})
	for _, epcIP := range epcIP4s {
		info := t.epcIDIPV4Infos[epcIP]
		fmt.Fprintf(sb, "%-6d  %-15s   %-15s %-6d  %-7d   %-10d   %-7d    %-8d  %-9d %d\n", epcIP>>32, utils.IpFromUint32(uint32(epcIP)).String(),
			utils.IpFromUint32(info.Host).String(), info.HostID, info.RegionID, info.DeviceType, info.DeviceID, info.SubnetID, info.PodNodeID, info.AZID)
	}

	if len(t.epcIDIPV6Infos) > 0 {
		sb.WriteString("\n\n")
		sb.WriteString("epcid   ipv6                                       host            hostID  regionID deviceType  deviceID subnetID  podNodeID azID\n")
		sb.WriteString("--------------------------------------------------------------------------------------------------------------------------------- \n")
	}
	epcIP6s := make([]EpcIDIPV6, 0)
	for epcIP, _ := range t.epcIDIPV6Infos {
		epcIP6s = append(epcIP6s, epcIP)
	}
	sort.Slice(epcIP6s, func(i, j int) bool {
		return epcIP6s[i].EpcID < epcIP6s[j].EpcID
	})
	for _, epcIP := range epcIP6s {
		info := t.epcIDIPV6Infos[epcIP]
		fmt.Fprintf(sb, "%-6d  %-40s   %-15s %-6d  %-7d  %-10d  %-7d  %-8d  %-9d %d\n", epcIP.EpcID, net.IP(epcIP.IP[:]).String(),
			utils.IpFromUint32(info.Host).String(), info.HostID, info.RegionID, info.DeviceType, info.DeviceID, info.SubnetID, info.PodNodeID, info.AZID)
	}

	t.lock.RUnlock()
	return sb.String()
}

func (t *PlatformInfoTable) Reload() error {
	var response *trident.SyncResponse
	err := t.Request(func(ctx context.Context) error {
		var err error
		request := trident.SyncRequest{
			BootTime:            proto.Uint32(t.bootTime),
			VersionPlatformData: proto.Uint64(t.versionPlatformData),
			CtrlIp:              proto.String("127.0.0.1"),
			ProcessName:         proto.String(t.processName),
		}
		client := trident.NewSynchronizerClient(t.GetClient())
		response, err = client.Sync(ctx, &request)
		return err
	})
	if err != nil {
		return err
	}

	if status := response.GetStatus(); status != trident.Status_SUCCESS {
		return fmt.Errorf("grpc response failed. responseStatus is %v", status)
	}

	newVersion := response.GetVersionPlatformData()
	if newVersion == t.versionPlatformData {
		return nil
	}

	platformData := trident.PlatformData{}
	if plarformCompressed := response.GetPlatformData(); plarformCompressed != nil {
		if err := platformData.Unmarshal(plarformCompressed); err != nil {
			log.Warningf("unmarshal grpc compressed platformData failed as %v", err)
			return err
		}
	}
	log.Infof("Update rpc platformdata version %d -> %d", t.versionPlatformData, newVersion)
	t.versionPlatformData = newVersion

	newEpcIDIPV4Infos := make(map[uint64]*Info)
	newEpcIDIPV6Infos := make(map[EpcIDIPV6]*Info)
	t.lock.Lock()
	for _, intf := range platformData.GetInterfaces() {
		updatePlatformInfos(newEpcIDIPV4Infos, newEpcIDIPV6Infos, intf)
	}
	t.epcIDIPV4Infos = newEpcIDIPV4Infos
	t.epcIDIPV6Infos = newEpcIDIPV6Infos
	t.lock.Unlock()
	return nil
}

func isIPV4(ipStr string) bool {
	for i := 0; i < len(ipStr); i++ {
		switch ipStr[i] {
		case '.':
			return true
		case ':':
			return false
		}
	}
	return false
}

func updatePlatformInfos(epcIDIPV4Infos map[uint64]*Info, epcIDIPV6Infos map[EpcIDIPV6]*Info, intf *trident.Interface) {
	epcID := intf.GetEpcId()
	deviceType := intf.GetDeviceType()
	deviceID := intf.GetDeviceId()
	podNodeID := intf.GetPodNodeId()
	azID := intf.GetAzId()
	regionID := intf.GetRegionId()
	hostStr := intf.GetLaunchServer()
	host := uint32(0)
	if hostStr != "" {
		host = utils.IpToUint32(utils.ParserStringIpV4(hostStr))
	}
	hostID := intf.GetLaunchServerId()

	epcIDIPV6 := EpcIDIPV6{}
	for _, ipRes := range intf.GetIpResources() {
		subnetID := ipRes.GetSubnetId()
		ipStr := ipRes.GetIp()
		if isIPV4(ipStr) {
			ipU32 := utils.IpToUint32(utils.ParserStringIpV4(ipStr))
			epcIDIPV4Infos[uint64(epcID)<<32|uint64(ipU32)] = &Info{
				Host:       host,
				HostID:     hostID,
				RegionID:   regionID,
				DeviceType: deviceType,
				DeviceID:   deviceID,
				SubnetID:   subnetID,
				PodNodeID:  podNodeID,
				AZID:       azID,
			}
		} else {
			netIP := net.ParseIP(ipStr)
			if netIP == nil {
				log.Warningf("IP(%s) parse failed", ipStr)
				continue
			}
			epcIDIPV6.EpcID = epcID
			copy(epcIDIPV6.IP[:], netIP)
			epcIDIPV6Infos[epcIDIPV6] = &Info{
				Host:       host,
				HostID:     hostID,
				RegionID:   regionID,
				DeviceType: deviceType,
				DeviceID:   deviceID,
				SubnetID:   subnetID,
				PodNodeID:  podNodeID,
				AZID:       azID,
			}
		}
	}
}

func RegisterPlatformDataCommand(ips []net.IP, port int) *cobra.Command {
	root := &cobra.Command{
		Use:   "rpc",
		Short: "pull policy from controller by rpc",
	}
	root.AddCommand(&cobra.Command{
		Use:   "platformData",
		Short: "get platformData from controller",
		Run: func(cmd *cobra.Command, args []string) {
			table := NewPlatformInfoTable(ips, port, "debug")
			table.Reload()
			fmt.Println(table)
		},
	})

	return root
}
