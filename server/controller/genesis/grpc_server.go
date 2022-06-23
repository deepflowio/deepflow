package genesis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.yunshan.net/metaflowys/metaflow/server/libs/queue"
	tridentcommon "github.com/metaflowys/metaflow/message/common"
	"github.com/metaflowys/metaflow/message/trident"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"server/controller/genesis/common"
	"server/controller/genesis/config"
)

func isInterestedHost(tType tridentcommon.TridentType) bool {
	types := []tridentcommon.TridentType{tridentcommon.TridentType_TT_PROCESS, tridentcommon.TridentType_TT_HOST_POD, tridentcommon.TridentType_TT_VM_POD, tridentcommon.TridentType_TT_PHYSICAL_MACHINE, tridentcommon.TridentType_TT_PUBLIC_CLOUD}
	for _, t := range types {
		if t == tType {
			return true
		}
	}
	return false
}

type TridentStats struct {
	VtapID       uint32
	Version      uint64
	IP           string
	Proxy        string
	ClusterID    string
	LastSeen     time.Time
	TridentType  tridentcommon.TridentType
	PlatformData *trident.GenesisPlatformData
}

type SynchronizerServer struct {
	cfg                 config.GenesisConfig
	conn                *grpc.ClientConn
	k8sQueue            queue.QueueWriter
	vinterfaceQueue     queue.QueueWriter
	vtapIDToVersion     map[uint32]uint64
	clusterIDToVersion  map[string]uint64
	vtapIDToLastSeen    map[uint32]time.Time
	clusterIDToLastSeen map[string]time.Time
	tridentStatsMap     map[uint32]TridentStats
	// trident.UnimplementedSynchronizerServer
}

func NewGenesisSynchronizerServer(cfg config.GenesisConfig, vinterfaceQueue, k8sQueue queue.QueueWriter) *SynchronizerServer {
	grpcServer := net.JoinHostPort(cfg.GRPCServerHost, strconv.Itoa(cfg.GRPCServerPort))
	conn, err := grpc.Dial(grpcServer, grpc.WithInsecure())
	if err != nil {
		log.Error(err.Error())
	}
	return &SynchronizerServer{
		cfg:                 cfg,
		conn:                conn,
		k8sQueue:            k8sQueue,
		vinterfaceQueue:     vinterfaceQueue,
		vtapIDToVersion:     map[uint32]uint64{},
		clusterIDToVersion:  map[string]uint64{},
		vtapIDToLastSeen:    map[uint32]time.Time{},
		clusterIDToLastSeen: map[string]time.Time{},
		tridentStatsMap:     map[uint32]TridentStats{},
	}
}

func (g *SynchronizerServer) GenesisSync(ctx context.Context, request *trident.GenesisSyncRequest) (*trident.GenesisSyncResponse, error) {
	client := trident.NewSynchronizerClient(g.conn)
	// 因为py版本的genesis暂未完全取消，所以trident上报的消息要先透传给py版的genesis
	_, err := client.GenesisSync(ctx, request)
	if err != nil {
		log.Warning(err.Error())
		return &trident.GenesisSyncResponse{}, err
	}

	stats := TridentStats{}
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
		stats.Proxy = peerIP.Addr.String()
	} else {
		remote = peerIP.Addr.String()
	}
	version := request.GetVersion()
	if version == 0 {
		msg := fmt.Sprintf("genesis sync ignore message with version 0 from %s", remote)
		log.Warning(msg)
		return &trident.GenesisSyncResponse{}, errors.New(msg)
	}
	vtapID := request.GetVtapId()
	k8sClusterID := request.GetKubernetesClusterId()
	if vtapID == 0 {
		log.Warningf("genesis sync received message with vtap_id 0 from %s", remote)
	}
	tType := request.GetTridentType()
	stats.IP = remote
	stats.VtapID = vtapID
	stats.Version = version
	stats.TridentType = tType
	stats.LastSeen = time.Now()
	platformData := request.GetPlatformData()
	if vtapID != 0 {
		if tStats, ok := g.tridentStatsMap[vtapID]; ok && platformData == nil {
			stats.PlatformData = tStats.PlatformData
		} else {
			stats.PlatformData = platformData
		}
		g.tridentStatsMap[vtapID] = stats
	}
	if !isInterestedHost(tType) {
		msg := fmt.Sprintf("genesis sync ignore message from %s trident %s vtap_id %v", tType, remote, vtapID)
		log.Debug(msg)
		return &trident.GenesisSyncResponse{Version: &version}, errors.New(msg)
	}
	var localVersion uint64
	if vtapID != 0 {
		now := time.Now()
		if lTime, ok := g.vtapIDToLastSeen[vtapID]; ok {
			lastTime := lTime
			var agingTime float64 = 0
			if g.cfg.AgingTime < g.cfg.VinterfaceAgingTime {
				agingTime = g.cfg.AgingTime
			} else {
				agingTime = g.cfg.VinterfaceAgingTime
			}
			if now.Sub(lastTime).Seconds() >= agingTime {
				g.vtapIDToVersion[vtapID] = 0
			}
		}
		g.vtapIDToLastSeen[vtapID] = now
		localVersion = g.vtapIDToVersion[vtapID]
	}
	if version == localVersion || platformData == nil {
		g.vinterfaceQueue.Put(
			VIFRPCMessage{
				peer:         remote,
				vtapID:       vtapID,
				k8sClusterID: k8sClusterID,
				msgType:      common.TYPE_RENEW,
				message:      request,
			},
		)
		return &trident.GenesisSyncResponse{Version: &localVersion}, nil
	}
	log.Infof("genesis sync received version %v -> %v from ip %s vtap_id %v", localVersion, version, remote, vtapID)
	g.vinterfaceQueue.Put(
		VIFRPCMessage{
			peer:         remote,
			vtapID:       vtapID,
			k8sClusterID: k8sClusterID,
			msgType:      common.TYPE_UPDATE,
			message:      request,
		},
	)
	if vtapID != 0 {
		g.vtapIDToVersion[vtapID] = version
	}
	return &trident.GenesisSyncResponse{Version: &version}, nil
}

func (g *SynchronizerServer) KubernetesAPISync(ctx context.Context, request *trident.KubernetesAPISyncRequest) (*trident.KubernetesAPISyncResponse, error) {
	client := trident.NewSynchronizerClient(g.conn)
	// 因为py版本的genesis暂未完全取消，所以trident上报的消息要先透传给py版的genesis
	_, err := client.KubernetesAPISync(ctx, request)
	if err != nil {
		log.Warning(err.Error())
		return &trident.KubernetesAPISyncResponse{}, err
	}

	stats := TridentStats{}
	remote := ""
	peerIP, _ := peer.FromContext(ctx)
	sourceIP := request.GetSourceIp()
	if sourceIP != "" {
		remote = sourceIP
		stats.Proxy = peerIP.Addr.String()
	} else {
		remote = peerIP.Addr.String()
	}
	vtapID := request.GetVtapId()
	if vtapID == 0 {
		log.Warningf("kubernetes api sync received message with vtap_id 0 from %s", remote)
	} else {
		vtapID = request.GetVtapId()
	}
	version := request.GetVersion()
	if version == 0 {
		msg := fmt.Sprintf("kubernetes api sync ignore message with version 0 from ip: %s, vtap id: %d", remote, vtapID)
		log.Warning(msg)
		return &trident.KubernetesAPISyncResponse{}, errors.New(msg)
	}
	clusterID := request.GetClusterId()
	if clusterID == "" {
		msg := fmt.Sprintf("kubernetes api sync ignore message with cluster id null from ip: %s, vtap id: %v", remote, vtapID)
		log.Warningf(msg)
		return &trident.KubernetesAPISyncResponse{}, errors.New(msg)
	}
	entries := request.GetEntries()

	stats.IP = remote
	stats.VtapID = vtapID
	stats.ClusterID = clusterID
	stats.LastSeen = time.Now()
	stats.Version = version
	g.tridentStatsMap[vtapID] = stats
	now := time.Now()
	if vtapID != 0 {
		if lastTime, ok := g.clusterIDToLastSeen[clusterID]; ok {
			if now.Sub(lastTime).Seconds() >= g.cfg.AgingTime {
				g.clusterIDToVersion[clusterID] = 0
			}
		}
		localVersion := g.clusterIDToVersion[clusterID]
		log.Infof("kubernetes api sync received version %v -> %v from ip %s vtap_id %v len %v", localVersion, version, remote, vtapID, len(entries))

		// 如果version有更新，但消息中没有任何kubernetes数据，触发trident重新上报数据
		if localVersion != version && len(entries) == 0 {
			return &trident.KubernetesAPISyncResponse{Version: &localVersion}, nil
		}

		// 正常推送消息到队列中
		g.k8sQueue.Put(K8SRPCMessage{
			peer:    remote,
			vtapID:  vtapID,
			msgType: 0,
			message: request,
		})

		// 更新内存中的last_seen和version
		g.clusterIDToLastSeen[clusterID] = now
		g.clusterIDToVersion[clusterID] = version
		return &trident.KubernetesAPISyncResponse{Version: &version}, nil
	} else {
		log.Infof("kubernetes api sync received version %v from ip %s no vtap_id", version, remote)
		//正常上报数据，才推送消息到队列中
		if len(entries) > 0 {
			g.k8sQueue.Put(K8SRPCMessage{
				peer:    remote,
				vtapID:  vtapID,
				msgType: 0,
				message: request,
			})
		}
		// 采集器未自动发现时，触发trident上报完整数据
		return &trident.KubernetesAPISyncResponse{}, nil
	}
}
