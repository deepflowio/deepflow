package genesis

import (
	"server/controller/cloud/config"
	"server/controller/cloud/model"
	"server/controller/common"
	"server/controller/db/mysql"

	"github.com/bitly/go-simplejson"
	"github.com/op/go-logging"
	uuid "github.com/satori/go.uuid"
)

var log = logging.MustGetLogger("cloud.genesis")

type Genesis struct {
	defaultVpc        bool
	name              string
	uuid              string
	uuidGenerate      string
	regionUuid        string
	azLcuuid          string
	defaultVpcName    string
	defaultRegionName string
}

func NewGenesis(domain mysql.Domain, cfg config.CloudConfig) (*Genesis, error) {
	config, err := simplejson.NewJson([]byte(domain.Config))
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &Genesis{
		name:              domain.Name,
		uuid:              domain.Lcuuid,
		uuidGenerate:      domain.DisplayName,
		defaultVpcName:    cfg.GenesisDefaultVpcName,
		defaultRegionName: cfg.GenesisDefaultRegionName,
		regionUuid:        config.Get("region_uuid").MustString(),
	}, nil
}

func (g *Genesis) CheckAuth() error {
	return nil
}

func (g *Genesis) GetCloudData() (model.Resource, error) {
	g.azLcuuid = ""
	g.defaultVpc = false

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
	return model.Resource{
		IPs:         ips,
		VMs:         vms,
		VPCs:        vpcs,
		Hosts:       hosts,
		Regions:     regions,
		Subnets:     subnets,
		Networks:    networks,
		VInterfaces: vinterfaces,
		AZs:         []model.AZ{az},
	}, nil
}
