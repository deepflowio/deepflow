package synchronize

import (
	api "github.com/metaflowys/metaflow/message/trident"
	context "golang.org/x/net/context"

	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/trisolaris"
)

type KubernetesClusterIDEvent struct {
}

func NewKubernetesClusterIDEvent() *KubernetesClusterIDEvent {
	return &KubernetesClusterIDEvent{}
}

func (k *KubernetesClusterIDEvent) GetKubernetesClusterID(ctx context.Context, in *api.KubernetesClusterIDRequest) (*api.KubernetesClusterIDResponse, error) {
	clusterID, err := common.GenerateKuberneteClusterIDByMD5(in.GetCaMd5())
	if err != nil {
		errorMsg := err.Error()
		return &api.KubernetesClusterIDResponse{ErrorMsg: &errorMsg}, nil
	}

	// cache clusterID & create kubernetes domain
	kubernetesInfo := trisolaris.GetGKubernetesInfo()
	kubernetesInfo.CacheClusterID(clusterID)

	return &api.KubernetesClusterIDResponse{ClusterId: &clusterID}, nil
}
