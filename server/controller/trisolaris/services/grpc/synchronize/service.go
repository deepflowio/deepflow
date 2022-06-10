package synchronize

import (
	context "golang.org/x/net/context"
	"google.golang.org/grpc"

	"server/controller/genesis"
	grpcserver "server/controller/trisolaris/server/grpc"
	api "gitlab.yunshan.net/yunshan/metaflow/message/trident"
)

type service struct {
	vTapEvent    *VTapEvent
	tsdbEvent    *TSDBEvent
	ntpEvent     *NTPEvent
	upgradeEvent *UpgradeEvent
}

func init() {
	grpcserver.Add(newService())
}

func newService() *service {
	return &service{
		vTapEvent:    NewVTapEvent(),
		tsdbEvent:    NewTSDBEvent(),
		ntpEvent:     NewNTPEvent(),
		upgradeEvent: NewUpgradeEvent(),
	}
}

func (s *service) Register(gs *grpc.Server) error {
	api.RegisterSynchronizerServer(gs, s)
	return nil
}

func (s *service) Sync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	return s.vTapEvent.Sync(ctx, in)
}

func (s *service) Push(r *api.SyncRequest, in api.Synchronizer_PushServer) error {
	if r.GetProcessName() == "trident" {
		s.vTapEvent.Push(r, in)
	} else {
		s.tsdbEvent.Push(r, in)
	}
	return nil
}

func (s *service) AnalyzerSync(ctx context.Context, in *api.SyncRequest) (*api.SyncResponse, error) {
	return s.tsdbEvent.AnalyzerSync(ctx, in)
}

func (s *service) Upgrade(r *api.UpgradeRequest, in api.Synchronizer_UpgradeServer) error {
	return s.upgradeEvent.Upgrade(r, in)
}

func (s *service) Query(ctx context.Context, in *api.NtpRequest) (*api.NtpResponse, error) {
	return s.ntpEvent.Query(ctx, in)
}

func (s *service) GenesisSync(ctx context.Context, in *api.GenesisSyncRequest) (*api.GenesisSyncResponse, error) {
	return genesis.Synchronizer.GenesisSync(ctx, in)
}

func (s *service) KubernetesAPISync(ctx context.Context, in *api.KubernetesAPISyncRequest) (*api.KubernetesAPISyncResponse, error) {
	return genesis.Synchronizer.KubernetesAPISync(ctx, in)
}
