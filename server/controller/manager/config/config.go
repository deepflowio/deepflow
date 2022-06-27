package config

import (
	cloudconfig "github.com/metaflowys/metaflow/server/controller/cloud/config"
	recorderconfig "github.com/metaflowys/metaflow/server/controller/recorder/config"
)

type TaskConfig struct {
	ResourceRecorderInterval uint32                        `default:"60" yaml:"resource_recorder_interval"`
	CloudCfg                 cloudconfig.CloudConfig       `yaml:"cloud"`
	RecorderCfg              recorderconfig.RecorderConfig `yaml:"recorder"`
}

type ManagerConfig struct {
	CloudConfigCheckInterval uint32     `default:"60" yaml:"cloud_config_check_interval"`
	TaskCfg                  TaskConfig `yaml:"task"`
}
