//go:build linux && xdp
// +build linux,xdp

/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// XDP socket配置文件，主要记录当前在哪个网卡的哪些队列上创建的XDP socket
// 配置文件根目录在XDPCONFIGFILEPATH中指定，每个配置文件按照网卡名称命名,
// 存储内容详见结构体IfaceConfig

package xdppacket

import (
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sync"
	"time"
)

var xdpConfig GlobleConfig // cache, 记录当前进程情况

const (
	XDPCONFIGFILEPATH = "/etc/xdp"
	MAX_RETRY_TIME    = 5
)

type GlobleConfig struct {
	cond   *sync.Cond
	using  bool
	config map[int]IfaceConfig
}

type IfaceConfig struct {
	First   int // 在网卡上创建第一个xdp socket时置1
	IfIndex int
	MapFd   int
	BpfFd   int

	UsedQueueCount uint32                // 申请使用的队列数量
	UsedQueues     [MAX_QUEUE_COUNT]bool // 记录队列的具体情况
}

func (g *GlobleConfig) condWait() {
	xdpConfig.cond.L.Lock()
	for xdpConfig.using {
		xdpConfig.cond.Wait()
	}
	xdpConfig.using = true
	xdpConfig.cond.L.Unlock()
}

func (g *GlobleConfig) condSignal() {
	xdpConfig.cond.L.Lock()
	xdpConfig.using = false
	xdpConfig.cond.L.Unlock()
	xdpConfig.cond.Signal()
}

func checkAndCreateDirectory() error {
	dir, err := os.Stat(XDPCONFIGFILEPATH)
	if err == nil && dir.IsDir() {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(XDPCONFIGFILEPATH, 0755); err != nil {
		return err
	}
	log.Debugf("make xdp config root directory %s ok", XDPCONFIGFILEPATH)
	return nil
}

func getConfigFileName(ifIndex int) (string, error) {
	iface, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return "", err
	}

	return path.Join(XDPCONFIGFILEPATH, iface.Name), nil
}

func read(file io.Reader) (*IfaceConfig, error) {
	config := IfaceConfig{}
	decoder := gob.NewDecoder(file)
	err := decoder.Decode(&config)
	if err != nil {
		return nil, err
	}
	log.Debugf("read xdp config %v", config)

	return &config, nil
}

func write(file io.Writer, config *IfaceConfig) error {
	log.Debugf("write xdp config %v", config)
	encoder := gob.NewEncoder(file)
	err := encoder.Encode(config)
	if err != nil {
		return err
	}

	return nil
}

func getIfaceConfig(ifIndex int) (*IfaceConfig, error) {
	fileName, err := getConfigFileName(ifIndex)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return read(file)
}

func setIfaceConfig(ifIndex int, config *IfaceConfig) error {
	fileName, err := getConfigFileName(ifIndex)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(fileName, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return write(file, config)
}

func checkFileExist(fileName string) bool {
	_, err := os.Stat(fileName)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true

}

func CheckIfaceConfigFileExist(ifIndex int) bool {
	fileName, err := getConfigFileName(ifIndex)
	if err != nil {
		return false
	}

	return checkFileExist(fileName)
}

// 如果网卡名对应的配置文件存在，则认为该网卡已被使用，返回失败
func CheckAndInitIfaceConfigFile(ifIndex int) (bool, error) {
	xdpConfig.condWait()
	defer xdpConfig.condSignal()
	fileName, err := getConfigFileName(ifIndex)
	if err != nil {
		return false, err
	}

	exist := checkFileExist(fileName)
	if exist {
		return true, nil
	}

	file, err := os.Create(fileName)
	if err != nil {
		return false, err
	}

	config := &IfaceConfig{IfIndex: ifIndex, First: 1}
	err = write(file, config)
	file.Close()
	if err != nil {
		os.Remove(fileName)
	}

	return false, err
}

func GetIfaceConfig(ifIndex int) (*IfaceConfig, error) {
	xdpConfig.condWait()
	config, err := getIfaceConfigFromCache(ifIndex)
	xdpConfig.condSignal()
	if err == nil {
		return &config, nil
	}

	times := 0
retry:
	xdpConfig.condWait()
	config2, err := getIfaceConfig(ifIndex)
	xdpConfig.condSignal()
	if err != nil {
		return nil, err
	}
	log.Debugf("now config is %v", config2)
	if config2.First > 0 {
		if times >= MAX_RETRY_TIME {
			return nil, fmt.Errorf("timeout as another xdp socket is initialzing "+
				"interface and consume more than %vs, now is %v", MAX_RETRY_TIME, config2)
		}
		times += 1
		time.Sleep(time.Second)
		goto retry
	}

	if config2.isInvalid() {
		return nil, fmt.Errorf("get invalid config(%v)", config2)
	}

	xdpConfig.condWait()
	xdpConfig.config[ifIndex] = *config2
	xdpConfig.condSignal()

	return config2, nil
}

func GetAndCheckIfaceConfig(ifIndex int, queueId int) (*IfaceConfig, error) {
	config, err := GetIfaceConfig(ifIndex)
	if err != nil {
		return nil, err
	}

	if !config.check(config, queueId) {
		return nil, fmt.Errorf("a xdp socket have been created on interface(%v)'s queueId %v", ifIndex, queueId)
	}

	return config, nil
}

func (c *IfaceConfig) isInvalid() bool {
	if _, err := net.InterfaceByIndex(c.IfIndex); err != nil ||
		c.MapFd < 0 || c.BpfFd < 0 || c.MapFd == c.BpfFd {
		return true
	}
	return false
}

func (c *IfaceConfig) check(newConfig *IfaceConfig, queueId int) bool {
	if c == nil || newConfig == nil ||
		c.IfIndex != newConfig.IfIndex ||
		c.MapFd != newConfig.MapFd ||
		c.BpfFd != newConfig.BpfFd {
		return false
	}

	if c.UsedQueues[queueId] {
		return false
	}
	return true
}

func updateIfaceConfig(newConfig *IfaceConfig, queueId int) (*IfaceConfig, error) {
	config, err := getIfaceConfigFromCache(newConfig.IfIndex)
	if err == nil {
		valid := config.check(newConfig, queueId)
		if !valid {
			return nil, fmt.Errorf("check config failed, %v vs %v", config, newConfig)
		}
		config.First = 0
	} else {
		config = *newConfig
	}

	config.UsedQueues[queueId] = true
	if config.UsedQueueCount < newConfig.UsedQueueCount {
		config.UsedQueueCount = newConfig.UsedQueueCount
	}

	xdpConfig.config[config.IfIndex] = config

	err = setIfaceConfig(config.IfIndex, &config)

	return &config, err
}

func UpdateIfaceConfig(newConfig *IfaceConfig, queueId int) (*IfaceConfig, error) {
	if newConfig == nil || newConfig.isInvalid() {
		return nil, fmt.Errorf("invalid param config %v", newConfig)
	}

	xdpConfig.condWait()
	defer xdpConfig.condSignal()
	return updateIfaceConfig(newConfig, queueId)
}

func getIfaceConfigFromCache(ifIndex int) (IfaceConfig, error) {
	config, ok := xdpConfig.config[ifIndex]

	if !ok {
		return config, fmt.Errorf("interface(%d) config not exist", ifIndex)
	}
	if config.isInvalid() {
		return config, fmt.Errorf("interface(%d) config(%v) is invalid", ifIndex, config)
	}
	return config, nil
}

func deleteIfaceConfigFile(ifIndex int) error {
	fileName, err := getConfigFileName(ifIndex)
	if err != nil {
		return err
	}
	exist := checkFileExist(fileName)
	if !exist {
		return nil
	}

	return os.Remove(fileName)
}

func DeleteIfaceConfig(ifIndex int) (*IfaceConfig, error) {
	xdpConfig.condWait()
	defer xdpConfig.condSignal()
	config, _ := getIfaceConfigFromCache(ifIndex)

	delete(xdpConfig.config, ifIndex)

	err := deleteIfaceConfigFile(ifIndex)
	return &config, err
}

func deleteIfaceQueue(ifIndex int, queueId int) (*IfaceConfig, error) {
	config, err := getIfaceConfigFromCache(ifIndex)
	if err != nil {
		return nil, err
	}

	config.UsedQueues[queueId] = false
	xdpConfig.config[ifIndex] = config

	setIfaceConfig(ifIndex, &config)
	return &config, nil
}

func DeleteIfaceQueue(ifIndex int, queueId int) (*IfaceConfig, error) {
	xdpConfig.condWait()
	defer xdpConfig.condSignal()
	return deleteIfaceQueue(ifIndex, queueId)
}

func init() {
	if err := checkAndCreateDirectory(); err != nil {
		log.Errorf("check and create xdp config root directory %s failed as %v", XDPCONFIGFILEPATH, err)
		os.Exit(1)
	}

	xdpConfig.config = make(map[int]IfaceConfig)
	lock := sync.Mutex{}
	xdpConfig.cond = sync.NewCond(&lock)
	xdpConfig.using = false
}
