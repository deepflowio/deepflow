package config

import (
	"net"
	"os"

	"github.com/op/go-logging"

	. "github.com/metaflowys/metaflow/server/controller/trisolaris/common"
)

var log = logging.MustGetLogger("trisolaris/config")

type Chrony struct {
	Host    string `default:"chrony" yaml:"host"`
	Port    uint32 `default:"123" yaml:"port"`
	Timeout uint32 `default:"1" yaml:"timeout"`
}

type Config struct {
	ListenPort               string   `default:"20014" yaml:"listen-port"`
	LogLevel                 string   `default:"info"`
	TsdbIP                   string   `yaml:"tsdb-ip"`
	Chrony                   Chrony   `yaml:"chrony"`
	SelfUpdateUrl            string   `default:"grpc" yaml:"self-update-url"`
	TridentPort              string   `default:"20035" yaml:"trident-port"`
	StatsdPort               string   `default:"20040" yaml:"statsd-port"`
	RemoteApiTimeout         uint16   `default:"30" yaml:"remote-api-timeout"`
	MaxEscapeSeconds         uint16   `default:"3600" yaml:"max-escape-seconds"`
	TridentRevision          string   `yaml:"trident-revision"`
	TridentTypeForUnkonwVtap uint16   `default:"1" yaml:"trident-type-for-unkonw-vtap"`
	TridentLinuxPath         string   `default:"/usr/local/deepflow/yum/trident" yaml:"trident-linux-path"`
	TridentWindowsPath       string   `default:"/usr/local/deepflow/yum/trident.exe" yaml:"trident-windows-path"`
	PlatformVips             []string `yaml:"platform-vips"`
	NodeType                 string   `default:"master" yaml:"node-type"`
	GrpcMaxMessageLength     int      `default:"104857600" yaml:"grpc-max-message-length"`
	RegionDomainPrefix       string   `yaml:"region-domain-prefix"`
	ClearKubernetesTime      int      `default:"600" yaml:"clear-kubernetes-time"`
	NodeIP                   string
	VTapCacheRefreshInterval int  `default:"300" yaml:"vtapcache-refresh-interval"`
	MetaDataRefreshInterval  int  `default:"60" yaml:"metadata-refresh-interval"`
	NodeRefreshInterval      int  `default:"60" yaml:"node-refresh-interval"`
	VTapAutoRegister         bool `default:"true" yaml:"vtap-auto-register"`
	DefaultTapMode           int  `yaml:"default-tap-mode"`
}

func (c *Config) Convert() {
	nodeIP := os.Getenv(NODE_IP_KEY)
	ip := net.ParseIP(nodeIP)
	if ip == nil {
		log.Errorf("IP(%s) address format is incorrect", nodeIP)
	} else {
		c.NodeIP = nodeIP
	}
}
