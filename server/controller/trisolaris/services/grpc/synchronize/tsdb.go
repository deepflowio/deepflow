package synchronize

import (
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	api "github.com/metaflowys/metaflow/message/trident"
	context "golang.org/x/net/context"

	"server/controller/trisolaris"
	. "server/controller/trisolaris/common"
	"server/controller/trisolaris/pushmanager"
)

var log = logging.MustGetLogger("trisolaris/synchronize")

type TSDBEvent struct{}

func NewTSDBEvent() *TSDBEvent {
	return &TSDBEvent{}
}

func (e *TSDBEvent) generateConfig(tsdbIP string) *api.Config {
	nodeInfo := trisolaris.GetGNodeInfo()
	pcapDataRetention := nodeInfo.GetPcapDataRetention()
	regionID := nodeInfo.GetRegionIDByTSDBIP(tsdbIP)
	return &api.Config{
		PcapDataRetention: proto.Uint32(pcapDataRetention),
		RegionId:          &regionID,
	}
}

func (e *TSDBEvent) AnalyzerSync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := trisolaris.GetGNodeInfo()
	versionPlatformData := nodeInfo.GetPlatformDataVersion()
	if versionPlatformData != in.GetVersionPlatformData() {
		log.Infof("ctrl_ip is %s, (platform data version %d -> %d), NAME:%s",
			tsdbIP, versionPlatformData, in.GetVersionPlatformData(),
			processName)
	}

	vTapInfo := trisolaris.GetGVTapInfo()
	// 只有roze进入数据节点注册流程，其他节点直接返回数据
	if processName == TSDB_PROCESS_NAME {
		log.Infof(
			"ctrl_ip:%s, cpu_num:%d, memory_size:%d, arch:%s, os:%s, "+
				"kernel_version:%s, pcap_data_mount_path:%s",
			tsdbIP, in.GetCpuNum(), in.GetMemorySize(),
			in.GetArch(), in.GetOs(),
			in.GetKernelVersion(),
			in.GetTsdbReportInfo())
		tsdbCache := nodeInfo.GetTSDBCache(tsdbIP)
		// 数据节点注册
		if tsdbCache == nil {
			nodeInfo.RegisterTSDB(in)
			return &api.SyncResponse{
				Status: &STATUS_FAILED,
			}, nil
		}
		if in.GetCommunicationVtaps() != nil {
			vTapInfo.UpdateTSDBVTapInfo(in.GetCommunicationVtaps(), tsdbIP)
			pcapDataMountPath := ""
			tsdbReportInfo := in.GetTsdbReportInfo()
			if tsdbReportInfo != nil {
				pcapDataMountPath = tsdbReportInfo.GetPcapDataMountPath()
			}
			tsdbCache.UpdateSystemInfo(
				int(in.GetCpuNum()),
				int64(in.GetMemorySize()),
				in.GetArch(),
				in.GetOs(),
				in.GetKernelVersion(),
				pcapDataMountPath)
			tsdbCache.UpdateSyncedAt(time.Now())
		}
	}

	configure := e.generateConfig(tsdbIP)
	platformData := []byte{}
	if versionPlatformData != in.GetVersionPlatformData() {
		platformData = nodeInfo.GetPlatformDataStr()
	}
	groups := nodeInfo.GetGroups()
	podIPs := nodeInfo.GetPodIPs()
	vTapIPs := vTapInfo.GetVTapIPs()
	return &api.SyncResponse{
		Status:              &STATUS_SUCCESS,
		PlatformData:        platformData,
		Groups:              groups,
		PodIps:              podIPs,
		VtapIps:             vTapIPs,
		VersionPlatformData: proto.Uint64(uint64(versionPlatformData)),
		Config:              configure,
	}, nil
}

func (e *TSDBEvent) pushResponse(in *api.SyncRequest) (*api.SyncResponse, error) {
	tsdbIP := in.GetCtrlIp()
	processName := in.GetProcessName()
	nodeInfo := trisolaris.GetGNodeInfo()
	versionPlatformData := nodeInfo.GetPlatformDataVersion()
	if processName == TSDB_PROCESS_NAME {
		tsdbCache := nodeInfo.GetTSDBCache(tsdbIP)
		if tsdbCache == nil {
			return &api.SyncResponse{
				Status: &STATUS_FAILED,
			}, fmt.Errorf("no find tsdb(%s) cache", tsdbIP)
		}
	}
	if versionPlatformData != in.GetVersionPlatformData() {
		log.Infof("ctrl_ip is %s, (platform data version %d -> %d), NAME:%s",
			tsdbIP, versionPlatformData, in.GetVersionPlatformData(),
			processName)
	}
	configure := e.generateConfig(tsdbIP)
	platformData := []byte{}
	if versionPlatformData != in.GetVersionPlatformData() {
		platformData = nodeInfo.GetPlatformDataStr()
	}
	groups := nodeInfo.GetGroups()
	podIPs := nodeInfo.GetPodIPs()
	vTapIPs := trisolaris.GetGVTapInfo().GetVTapIPs()
	return &api.SyncResponse{
		Status:              &STATUS_SUCCESS,
		PlatformData:        platformData,
		Groups:              groups,
		PodIps:              podIPs,
		VtapIps:             vTapIPs,
		VersionPlatformData: proto.Uint64(uint64(versionPlatformData)),
		Config:              configure,
	}, nil
}

func (e *TSDBEvent) Push(r *api.SyncRequest, in api.Synchronizer_PushServer) error {
	var err error
	for {
		response, err := e.pushResponse(r)
		if err != nil {
			log.Error(err)
			in.Send(response)
			break
		}
		err = in.Send(response)
		if err != nil {
			log.Error(err)
			break
		}
		pushmanager.Wait()
	}
	log.Info("exit push", r.GetCtrlIp(), r.GetCtrlMac())
	return err
}
