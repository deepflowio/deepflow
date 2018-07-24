package rpc

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"regexp"
	"time"

	"github.com/golang/protobuf/proto"
	"gopkg.in/yaml.v2"

	"gitlab.x.lan/yunshan/droplet/protobuf"
)

type RuntimeConfig struct {
	MaxCPUs            uint          `yaml:"max-cpus"`
	SyncInterval       time.Duration `yaml:"sync-interval"`
	GlobalPpsThreshold uint64        `yaml:"global-pps-threshold"`
	TapInterfaceRegex  string        `yaml:"tap-interface-regex"`

	OutputInterface string `yaml:"output-interface"`
	OutputVlan      uint16 `yaml:"output-vlan"`
	MTU             uint32 `yaml:"mtu"`

	SourceMac string `yaml:"source-mac"`
	SourceIp  string `yaml:"source-ip"`

	AnalyzerGwMac string `yaml:"analyzer-gw-mac"`
	AnalyzerIp    string `yaml:"analyzer-ip"`
	VtepGwMac     string `yaml:"vtep-gw-mac"`
	VtepIp        string `yaml:"vtep-ip"`
}

func (c *RuntimeConfig) Validate() error {
	if c.SyncInterval < time.Second || time.Hour < c.SyncInterval {
		return errors.New(fmt.Sprintf("sync-interval %s not in [1s, 1h]", c.SyncInterval.String()))
	}

	if net.ParseIP(c.SourceIp) == nil {
		return errors.New("Parse source-ip invalid")
	}
	if c.SourceMac != "" {
		if _, err := net.ParseMAC(c.SourceMac); err != nil {
			return errors.New("source-mac invalid")
		}
	}
	// 虽然RFC 791里最低MTU是68，但是此时compressor会崩溃，
	// 所以MTU最低限定到200以确保trident能够成功运行
	if c.MTU < 200 {
		return errors.New("MTU specified smaller than 200")
	}

	if c.OutputVlan > 4095 {
		return errors.New("output-vlan out of range")
	}
	if _, err := net.ParseMAC(c.AnalyzerGwMac); err != nil {
		return errors.New("analyzer-gw-mac invalid")
	}
	if net.ParseIP(c.AnalyzerIp) == nil {
		return errors.New("analyzer-ip invalid")
	}
	if _, err := net.ParseMAC(c.VtepGwMac); err != nil {
		return errors.New("vtep-gw-mac invalid")
	}
	if net.ParseIP(c.VtepIp) == nil {
		return errors.New("analyzer-ip invalid")
	}

	if _, err := regexp.Compile(c.TapInterfaceRegex); err != nil {
		return errors.New("malformed tap-interface-regex")
	}

	return nil
}

func (c *RuntimeConfig) Equal(cfg *RuntimeConfig) bool {
	return reflect.DeepEqual(c, cfg)
}

func (c *RuntimeConfig) Unmarshal(bytes []byte) error {
	if err := yaml.Unmarshal(bytes, c); err != nil {
		return err
	}
	c.SyncInterval *= time.Second
	return nil
}

func (c *RuntimeConfig) Load(path string) error {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	if err = c.Unmarshal(bytes); err != nil {
		return err
	}
	if err = c.Validate(); err != nil {
		return err
	}
	return nil
}

func ConvertRpcConfig(cfg *protobuf.Config) RuntimeConfig {
	return RuntimeConfig{
		MaxCPUs:            uint(cfg.GetMaxCpus()),
		SyncInterval:       time.Duration(cfg.GetSyncInterval()) * time.Second,
		GlobalPpsThreshold: cfg.GetGlobalPpsThreshold(),
		TapInterfaceRegex:  cfg.GetTapInterfaceRegex(),
		OutputInterface:    cfg.GetOutputInterface(),
		OutputVlan:         uint16(cfg.GetOutputVlan()),
		MTU:                cfg.GetMtu(),
		SourceMac:          cfg.GetSourceMac(),
		SourceIp:           cfg.GetSourceIp(),
		AnalyzerGwMac:      cfg.GetAnalyzerGwMac(),
		AnalyzerIp:         cfg.GetAnalyzerIp(),
		VtepGwMac:          cfg.GetVtepGwMac(),
		VtepIp:             cfg.GetVtepIp(),
	}
}

func (cfg *RuntimeConfig) ToRpcConfig() *protobuf.Config {
	return &protobuf.Config{
		MaxCpus:            proto.Uint32(uint32(cfg.MaxCPUs)),
		SyncInterval:       proto.Uint32(uint32(cfg.SyncInterval / time.Second)),
		GlobalPpsThreshold: proto.Uint64(cfg.GlobalPpsThreshold),
		TapInterfaceRegex:  proto.String(cfg.TapInterfaceRegex),
		OutputInterface:    proto.String(cfg.OutputInterface),
		OutputVlan:         proto.Uint32(uint32(cfg.OutputVlan)),
		Mtu:                proto.Uint32(cfg.MTU),
		SourceMac:          proto.String(cfg.SourceMac),
		SourceIp:           proto.String(cfg.SourceIp),
		AnalyzerGwMac:      proto.String(cfg.AnalyzerGwMac),
		AnalyzerIp:         proto.String(cfg.AnalyzerIp),
		VtepGwMac:          proto.String(cfg.VtepGwMac),
		VtepIp:             proto.String(cfg.VtepIp),
	}
}
