package baidubce

import (
	"encoding/json"

	"github.com/baidubce/bce-sdk-go/services/cce"

	"server/controller/cloud/model"
	"server/controller/common"
)

func (b *BaiduBce) getSubDomains(region model.Region, vpcIdToLcuuid map[string]string) ([]model.SubDomain, error) {
	var retSubDomains []model.SubDomain

	log.Debug("get sub_domains starting")

	cceClient, _ := cce.NewClient(b.secretID, b.secretKey, "cce."+b.endpoint)
	marker := ""
	args := &cce.ListClusterArgs{}
	results := make([]*cce.ListClusterResult, 0)
	for {
		args.Marker = marker
		result, err := cceClient.ListClusters(args)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	for _, r := range results {
		for _, cluster := range r.Clusters {
			vpcLcuuid, ok := vpcIdToLcuuid[cluster.VpcId]
			if !ok {
				log.Debugf("cluster (%s) vpc (%s) not found", cluster.ClusterUuid, cluster.VpcId)
				continue
			}

			config := map[string]string{
				"vpc_uuid":        vpcLcuuid,
				"cluster_id":      cluster.ClusterUuid,
				"port_name_regex": "",
				"vtap_id":         "",
				"controller_ip":   "",
			}
			configJson, _ := json.Marshal(config)
			retSubDomains = append(retSubDomains, model.SubDomain{
				Lcuuid:      common.GenerateUUID(cluster.ClusterUuid),
				Name:        cluster.ClusterName,
				DisplayName: cluster.ClusterUuid,
				ClusterID:   cluster.ClusterUuid,
				VpcUUID:     vpcLcuuid,
				Config:      string(configJson),
			})
		}
	}
	log.Debug("get sub_domains complete")
	return retSubDomains, nil
}
