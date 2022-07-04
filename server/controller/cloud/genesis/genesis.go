package genesis

import (
	"errors"
	"github.com/metaflowys/metaflow/server/controller/cloud/config"
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/genesis"
	"github.com/metaflowys/metaflow/server/controller/statsd"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"
)

var log = logging.MustGetLogger("cloud.genesis")

type Genesis struct {
	defaultVpc        bool
	Name              string
	uuid              string
	UuidGenerate      string
	regionUuid        string
	azLcuuid          string
	defaultVpcName    string
	defaultRegionName string
	cloudStatsd       statsd.CloudStatsd
}

func NewGenesis(domain mysql.Domain, cfg config.CloudConfig) (*Genesis, error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &Genesis{
		Name:              domain.Name,
		uuid:              domain.Lcuuid,
		UuidGenerate:      domain.DisplayName,
		defaultVpcName:    cfg.GenesisDefaultVpcName,
		defaultRegionName: cfg.GenesisDefaultRegionName,
		regionUuid:        config.Get("region_uuid").MustString(),
		cloudStatsd: statsd.CloudStatsd{
			APICount: make(map[string][]int),
			APICost:  make(map[string][]int),
			ResCount: make(map[string][]int),
			TaskCost: make(map[string][]int),
		},
	}, nil
}

func (g *Genesis) CheckAuth() error {
	return nil
}

func (g *Genesis) GetStatter() statsd.StatsdStatter {
	globalTags := map[string]string{
		"domain_name": g.Name,
		"domain":      g.UuidGenerate,
		"platform":    "genesis",
	}

	return statsd.StatsdStatter{
		GlobalTags: globalTags,
		Element:    statsd.GetCloudStatsd(g.cloudStatsd),
	}
}

func (g *Genesis) GetCloudData() (model.Resource, error) {
	g.azLcuuid = ""
	g.defaultVpc = false
	g.cloudStatsd.APICount = map[string][]int{}
	g.cloudStatsd.APICost = map[string][]int{}
	g.cloudStatsd.ResCount = map[string][]int{}
	g.cloudStatsd.TaskCost = map[string][]int{}
	startTime := time.Now()

	if genesis.GenesisService == nil {
		return model.Resource{}, errors.New("genesis service is nil")
	}

	regions, err := g.getRegion()
	if err != nil {
		return model.Resource{}, err
	}

	az, err := g.getAZ()
	if err != nil {
		return model.Resource{}, err
	}

	vpcs, err := g.getVPCs()
	if err != nil {
		return model.Resource{}, err
	}

	hosts, err := g.getHosts()
	if err != nil {
		return model.Resource{}, err
	}

	networks, err := g.getNetworks()
	if err != nil {
		return model.Resource{}, err
	}

	subnets, err := g.getSubnets()
	if err != nil {
		return model.Resource{}, err
	}

	vms, err := g.getVMs()
	if err != nil {
		return model.Resource{}, err
	}

	vinterfaces, err := g.getVinterfaces()
	if err != nil {
		return model.Resource{}, err
	}

	ips, err := g.getIPs()
	if err != nil {
		return model.Resource{}, err
	}
	if g.defaultVpc {
		vpc := model.VPC{
			Lcuuid:       common.GetUUID(g.defaultVpcName, uuid.Nil),
			Name:         g.defaultVpcName,
			RegionLcuuid: g.regionUuid,
		}
		vpcs = append(vpcs, vpc)
	}

	resource := model.Resource{
		IPs:         ips,
		VMs:         vms,
		VPCs:        vpcs,
		Hosts:       hosts,
		Regions:     regions,
		Subnets:     subnets,
		Networks:    networks,
		VInterfaces: vinterfaces,
		AZs:         []model.AZ{az},
	}
	g.cloudStatsd.ResCount = statsd.GetResCount(resource)
	g.cloudStatsd.TaskCost[g.UuidGenerate] = []int{int(time.Now().Sub(startTime).Milliseconds())}
	statsd.MetaStatsd.RegisterStatsdTable(g)
	return resource, nil
}
