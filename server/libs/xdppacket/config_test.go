//go:build linux && xdp
// +build linux,xdp

/*
 * Copyright (c) 2024 Yunshan Networks
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

package xdppacket

import (
	"reflect"
	"testing"
	"time"
)

func TestIsIfaceConfigExist(t *testing.T) {
	// init
	DeleteIfaceConfig(1)

	exist, err := IsIfaceConfigExist(1)
	if err != nil {
		t.Error(err)
	}
	if exist {
		t.Errorf("config file should be not exist")
	}

	exist, err = IsIfaceConfigExist(1)
	if err != nil {
		t.Error(err)
	}
	if !exist {
		t.Errorf("config file should be exist")
	}

	// clear
	DeleteIfaceConfig(1)
}

func TestSetAndGetIfaceConfig(t *testing.T) {
	// init
	DeleteIfaceConfig(1)

	_, err := GetIfaceConfig(1)
	if err == nil {
		t.Errorf("config file not exist now")
	}

	_, err = IsIfaceConfigExist(1)
	if err != nil {
		t.Error(err)
	}

	_, err = GetIfaceConfig(1)
	if err == nil {
		t.Errorf("can not read config as is initing")
	}

	config := &IfaceConfig{IfIndex: 1, MapFd: 1, BpfFd: 2}
	config2, err := UpdateIfaceConfig(config, 1)
	if err != nil {
		t.Errorf("update config failed as %v", err)
	}
	usedQueues := [MAX_QUEUE_COUNT]bool{false, true}
	expect := &IfaceConfig{IfIndex: 1, MapFd: 1, BpfFd: 2, UsedQueues: usedQueues}
	if !reflect.DeepEqual(expect, config2) {
		t.Errorf("expect config should be %#v, but actual is %v", expect, config2)
	}

	config, err = GetIfaceConfig(1)
	if err != nil {
		t.Errorf("read config failed as %v", config)
	}
	if !reflect.DeepEqual(expect, config) {
		t.Errorf("expect config should be %#v, but actual is %v", expect, config)
	}

	// clear
	DeleteIfaceConfig(1)
}

func integrate(t *testing.T) {
	exist, err := IsIfaceConfigExist(1)
	if err != nil {
		t.Errorf("check config exist failed %v", err)
		return
	}

	if exist {
		_, err := GetIfaceConfig(1)
		if err != nil {
			t.Errorf("get xdp config failed %v", err)
			return
		}
	} else {
		config := &IfaceConfig{IfIndex: 1, MapFd: 1, BpfFd: 2}
		config2, err := UpdateIfaceConfig(config, 1)
		if err != nil {
			t.Errorf("update xdp config failed %v", err)
			return
		}
		usedQueues := [MAX_QUEUE_COUNT]bool{false, true}
		expect := &IfaceConfig{IfIndex: 1, MapFd: 1, BpfFd: 2, UsedQueues: usedQueues}
		if !reflect.DeepEqual(config2, expect) {
			t.Errorf("expect config is %v, but actual write is %v", expect, config2)
		}

		actual, err := GetIfaceConfig(1)
		if !reflect.DeepEqual(config2, actual) {
			t.Errorf("expect config is %v, but actual read is %v", config2, actual)
		}
	}

	time.Sleep(2 * time.Second)
	_, err = DeleteIfaceConfig(1)
	if err != nil {
		t.Errorf("DeleteIfaceConfig failed %v", err)
	}
}

func TestOneXDP(t *testing.T) {
	// init
	DeleteIfaceConfig(1)

	integrate(t)

	// clear
	DeleteIfaceConfig(1)
}

func TestSeqXDP(t *testing.T) {
	// init
	DeleteIfaceConfig(1)

	for i := 0; i < 2; i++ {
		integrate(t)
	}

	// clear
	DeleteIfaceConfig(1)
}

func TestConcurrentXDP(t *testing.T) {
	cnt := 0
	fun := func(i int, t *testing.T) {
		integrate(t)
		cnt += 1
	}

	// init
	DeleteIfaceConfig(1)

	for i := 0; i < 2; i++ {
		go fun(i, t)
	}

	for cnt < 2 {
	}

	// clear
	DeleteIfaceConfig(1)
}
