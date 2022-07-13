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

package xdppacket

import (
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOption(t *testing.T) {
	opt, err := parseOptions()
	if err != nil {
		t.Errorf("defaultOpt(%v) is invalid as %v", defaultOpt, err)
	}
	if !reflect.DeepEqual(*opt, defaultOpt) {
		t.Errorf("invalid default Option:")
		t.Errorf("actual option is %v", opt)
		t.Errorf("default option is %v", defaultOpt)
	}
	correctOpts := []interface{}{OptPollTimeout(time.Millisecond),
		IO_MODE_NONPOLL, OptQueueCount(1)}
	for _, opt := range correctOpts {
		_, err := parseOptions(opt)
		if err != nil {
			t.Errorf("option check failed as %v", err)
		}
	}

	errorOpts := []interface{}{OptNumFrames(10), OptRingSize(100),
		OptXDPMode(0)}
	for _, opt := range errorOpts {
		_, err := parseOptions(opt)
		if err == nil {
			t.Errorf("option check failed as %v", err)
		}
	}
}

func TestConfigXDPPacket(t *testing.T) {
	xsk := &XDPSocket{}
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		log.Debug("1")
	}
	xsk.sockFd = fd

	err = xsk.configXDPSocket(&defaultOpt)
	if err != nil {
		log.Debug("2")
	}
}

func TestClearIfaceResidueXDPResources(t *testing.T) {
	err := ClearIfaceResidueXDPResources("lo")
	if err != nil {
		t.Error(err)
	}
}
