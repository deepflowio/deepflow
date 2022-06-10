package config

var CONF *CloudConfig

type CloudConfig struct {
	KubernetesGatherInterval uint32 `default:"60" yaml:"kubernetes_gather_interval"`
	AliyunRegionName         string `default:"cn-beijing" yaml:"aliyun_region_name"`
	GenesisDefaultRegionName string `default:"系统默认" yaml:"genesis_default_region"`
	GenesisDefaultVpcName    string `default:"default_vpc" yaml:"genesis_default_vpc"`
	HostnameToIPFile         string `default:"/etc/hostname_to_ip.csv" yaml:"hostname_to_ip_file"`
	DNSEnable                bool   `default:"false" yaml:"dns_enable"`
	HTTPTimeout              int    `default:"30" yaml:"http_timeout"`
}

func SetCloudGlobalConfig(c CloudConfig) {
	CONF = &CloudConfig{
		HostnameToIPFile: c.HostnameToIPFile,
		DNSEnable:        c.DNSEnable,
		HTTPTimeout:      c.HTTPTimeout,
	}

}
