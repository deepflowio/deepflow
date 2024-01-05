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

// C语言实现，ebpf用户态部分，主要实现2个功能：
// 1. 加载ebpf程序到内核，并更新map
// 2. 清除ebpf资源

// #cgo CFLAGS: -I/usr/include/bpf
// #cgo LDFLAGS: -L/usr/lib64/ -lbpf -lelf
/*
#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <net/if.h>

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define EBPF_PROG_NAME "/usr/sbin/xdpsock_kern.o"
#define BPF_FS_PATH "/sys/fs/bpf/"
#define SOCK_MAP_PATH BPF_FS_PATH "xsks_map"
#define QID_MAP_PATH BPF_FS_PATH "qidconf_map"

// 1. 加载ebpf程序到内核(网卡)
int load_ebpf_prog(int ifindex, int xdp_mode, void *prog_fd, void *xsks_map_fd) {
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct bpf_object *obj = NULL;
	struct bpf_map *map;
	int fd = -1, map_fd = -1;
	char file_name[256] = {0}, if_name[64] = {0};

	if (!prog_fd || !xsks_map_fd)
	{
		fprintf(stderr, "ERROR: NULL pointer\n");
		goto failed;
	}

	if (if_indextoname(ifindex, if_name) == NULL) {
		fprintf(stderr, "ERROR: if_nametoindex \"%s\"\n",
		strerror(errno));
		goto failed;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
        goto failed;
	}

	if (access(EBPF_PROG_NAME, F_OK)) {
		fprintf(stderr, "ERROR: %s ebpf file not exist\n", EBPF_PROG_NAME);
		goto failed;
	}
	prog_load_attr.file = EBPF_PROG_NAME;
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &fd)) {
		fprintf(stderr, "ERROR: load bpf program failed\n");
        goto failed;
	}
	if (fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n",
			strerror(fd));
        goto failed;
	}

	map = bpf_object__find_map_by_name(obj, "xsks_map");
		map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(map_fd));
        goto failed;
	}
	fprintf(stderr, "xsks_map fd: %d\n", map_fd);

	if (bpf_set_link_xdp_fd(ifindex, fd, xdp_mode) < 0) {
		fprintf(stderr, "ERROR: set xdp(mode:%d) fd(%d) to interface(%d) failed as %s\n",
		xdp_mode, fd, ifindex, strerror(errno));
        goto failed;
	}

	*(int*)prog_fd = fd;
	*(int*)xsks_map_fd = map_fd;
	return 0;

failed:
	if (fd < 0) {
		bpf_object__close(obj);
	}
	if (map_fd < 0) {
		close(map_fd);
	}
	return -1;
}

// 2. 更新map，将socket fd，queue id写入map
int set_ebpf_map(int xsks_map_fd, int queue_id, int sock_fd) {
	int ret;
	ret = bpf_map_update_elem(xsks_map_fd, &queue_id, &sock_fd, 0);
	if (ret) {
		fprintf(stderr, "ERROR: bpf_map_update_elem (sock_fd:%d, queue_id:%d) failed as %s\n",
		sock_fd, queue_id, strerror(errno));
        return -1;
	}
	return 0;
}

// 3. 清除ebpf program fd
int unpinEbpfProg(int ifindex, int xdp_mode) {
	if (bpf_set_link_xdp_fd(ifindex, -1, xdp_mode) < 0) {
		fprintf(stderr, "ERROR: unpin ebpf prog failed as %s\n",
			strerror(errno));
        return -1;
	}

    return 0;
}

// 4. 查询map是否为空; 0:empty, 1:not empty, -1:error
// BPF_MAP_TYPE_XSKMAP不支持bpf_map_lookup_elem
int check_map_is_empty(int xsks_map_fd) {
	int ret, key=-1, next_key, value;

	while (1) {
		ret = bpf_map_get_next_key(xsks_map_fd, &key, &next_key);
		if (ret) {
			if (errno == ENOENT) {
				break;
			}

			fprintf(stderr, "ERROR: bpf_map_get_next_key (xsks_map_fd:%d) failed as %s\n",
				xsks_map_fd, strerror(errno));
			return -1;
		}
		fprintf(stderr, "INFO: next_key:%d\n", next_key);

		ret = bpf_map_lookup_elem(xsks_map_fd, &next_key, &value);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_lookup_elem (xsks_map_fd:%d) failed as %s\n",
				xsks_map_fd, strerror(errno));
			return -1;
		}
		fprintf(stderr, "INFO: key:%d, value:%d\n", next_key, value);

		if (value != 0) {
			return 1;
		}

		key = next_key;
	}

	return 0;
}

// 5. 删除map数据，将socket fd，queue id从map删除
int del_ebpf_map(int xsks_map_fd, int queue_id) {
	int ret;
	ret = bpf_map_delete_elem(xsks_map_fd, &queue_id);
	if (ret) {
		fprintf(stderr, "ERROR: bpf_map_delete_elem (xsks_map_fd:%d, queueId:%d) failed as %s\n",
			xsks_map_fd, queue_id, strerror(errno));
        return -1;
	}

	return 0;
}
*/
import "C"

import (
	"fmt"
	"net"
	"os/exec"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const ERROR_FD = -1

// XDP socket结构
type XDPSocket struct {
	sockFd  int
	ifIndex int
	// UMEM
	framesBulk []byte
	queueId    int

	progFd    int
	xsksMapFd int
	xdpMode   OptXDPMode

	rx XDPDescQueue
	tx XDPDescQueue
	fq XDPUmemQueue
	cq XDPUmemQueue
}

// 实现XDP的SETSOCKOPT系统调用
func setXDPSockopt(s int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s), unix.SOL_XDP,
		uintptr(name), uintptr(val), vallen, 0)
	if e1 != 0 {
		err = error(e1)
	}
	return
}

// 实现XDP的GETSOCKOPT系统调用
func getXDPSockopt(s int, name int, val unsafe.Pointer, vallen unsafe.Pointer) (err error) {
	_, _, e1 := unix.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), unix.SOL_XDP,
		uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = error(e1)
	}
	return
}

// 注册XDP UMEM
func setOptUmemreg(s int, ur *unix.XDPUmemReg) error {
	return setXDPSockopt(s, unix.XDP_UMEM_REG, unsafe.Pointer(ur),
		unsafe.Sizeof(*ur))
}

// 设置XDP fq队列size
func setOptUmemFillring(s, size int) error {
	return setXDPSockopt(s, unix.XDP_UMEM_FILL_RING, unsafe.Pointer(&size),
		4)
}

// 设置XDP cq队列size
func setOptUmemCompletionring(s, size int) error {
	return setXDPSockopt(s, unix.XDP_UMEM_COMPLETION_RING, unsafe.Pointer(&size),
		4)
}

// 获取XDP 内核统计
func getOptXDPStats(s int) (*unix.XDPStatistics, error) {
	stats := unix.XDPStatistics{}
	vallen := unsafe.Sizeof(stats)

	err := getXDPSockopt(s, unix.XDP_STATISTICS, unsafe.Pointer(&stats),
		unsafe.Pointer(&vallen))
	if err != nil {
		return nil, errors.Wrap(err, "get sockopt XDP_STATISTICS failed")
	}

	return &stats, nil
}

// 获取XDP MmapOffsets
func getOptXDPMmapOffsets(s int) (*unix.XDPMmapOffsets, error) {
	var offset unix.XDPMmapOffsets
	vallen := unsafe.Sizeof(offset)
	err := getXDPSockopt(s, unix.XDP_MMAP_OFFSETS, unsafe.Pointer(&offset),
		unsafe.Pointer(&vallen))

	if err != nil {
		return nil, errors.Wrap(err, "get sockopt XDP_MMAP_OFFSETS failed")
	}

	return &offset, nil
}

// 设置XDP MmapOffsets
func setOptXDPMmapOffsets(s int, offset *unix.XDPMmapOffsets) error {
	return setXDPSockopt(s, unix.XDP_MMAP_OFFSETS, unsafe.Pointer(offset),
		unsafe.Sizeof(*offset))
}

// 设置XDP rx队列size
func setOptXDPRxRing(s, size int) error {
	return setXDPSockopt(s, unix.XDP_RX_RING, unsafe.Pointer(&size),
		4)
}

// 设置XDP tx队列size
func setOptXDPTxRing(s, size int) error {
	return setXDPSockopt(s, unix.XDP_TX_RING, unsafe.Pointer(&size),
		4)
}

// 设置XDP 内核各队列size, 并通过Mmap获取队列地址；然后初始化用户态队列结构
func (x *XDPSocket) configQueue(offsets *unix.XDPMmapOffsets, options *XDPOptions) error {
	sockFd := x.sockFd
	ringSize := int(options.ringSize)
	frameSize := int(options.frameSize)
	err := setOptUmemFillring(sockFd, ringSize)
	if err != nil {
		return errors.Wrap(err, "set Fill ring failed")
	}
	err = setOptUmemCompletionring(sockFd, ringSize)
	if err != nil {
		return errors.Wrap(err, "set Completion ring failed")
	}

	fqAddr, err := unix.Mmap(sockFd, unix.XDP_UMEM_PGOFF_FILL_RING,
		int(offsets.Fr.Desc)+ringSize*8,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return errors.Wrap(err, "mmap XDP_UMEM_PGOFF_FILL_RING failed")
	}
	x.fq.initQueue(fqAddr, offsets.Fr, ringSize)

	// 初始化fq队列，将umem前ringSize个block地址写入fq队列
	// 表示已完成对rx队列中全部包的读取
	// 因内核会对block地址的合法性进行检查，block地址不能超过
	// umem.Size，故XDP不能支持全双工(同时收发)
	addrs := make([]uint64, ringSize)
	for i := 0; i < ringSize; i++ {
		addrs[i] = uint64(i * frameSize)
	}
	err = x.fq.enqueue(addrs, uint32(ringSize))
	if err != nil {
		return errors.Wrapf(err, "init fill queue failed")
	}
	log.Debugf("actual fq info:\n\t%v", x.fq.GetDetail())

	cqAddr, err := unix.Mmap(sockFd, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(offsets.Cr.Desc)+ringSize*8,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return errors.Wrap(err, "mmap XDP_UMEM_PGOFF_COMPLETION_RING failed")
	}
	x.cq.initQueue(cqAddr, offsets.Cr, ringSize)

	err = setOptXDPRxRing(sockFd, ringSize)
	if err != nil {
		return errors.Wrap(err, "set rx ring failed")
	}
	err = setOptXDPTxRing(sockFd, ringSize)
	if err != nil {
		return errors.Wrap(err, "set tx ring failed")
	}

	valSize := int(unsafe.Sizeof(unix.XDPDesc{}))
	rxAddr, err := unix.Mmap(sockFd, unix.XDP_PGOFF_RX_RING,
		int(offsets.Rx.Desc)+ringSize*valSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return errors.Wrap(err, "mmap  XDP_PGOFF_RX_RING failed")
	}
	x.rx.initQueue(rxAddr, offsets.Rx, ringSize)

	valSize = int(unsafe.Sizeof(unix.XDPDesc{}))
	txAddr, err := unix.Mmap(sockFd, unix.XDP_PGOFF_TX_RING,
		int(offsets.Tx.Desc)+ringSize*valSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return errors.Wrap(err, "mmap XDP_PGOFF_TX_RING failed")
	}
	x.tx.initQueue(txAddr, offsets.Tx, ringSize)

	return nil
}

func (x *XDPSocket) clearQueue() {
	if x.rx.raw != nil {
		x.rx.clearQueue()
	}
	if x.tx.raw != nil {
		x.tx.clearQueue()
	}
	if x.fq.raw != nil {
		x.fq.clearQueue()
	}
	if x.cq.raw != nil {
		x.cq.clearQueue()
	}
}

// 配置XDP socket内核相关参数，并初始化用户态队列结构
func (x *XDPSocket) configXDPSocket(options *XDPOptions) error {
	var err error

	sockFd := x.sockFd
	umemLen := int(options.frameSize) * int(options.numFrames)

	// 不直接用make slice，避免将go的堆暴露给OS、避免受GC影响
	x.framesBulk, err = unix.Mmap(-1, 0, umemLen,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		return errors.Wrap(err, "mmap UMEM failed")
	}

	ur := &unix.XDPUmemReg{
		Addr:     uint64(reflect.ValueOf(x.framesBulk).Pointer()),
		Len:      uint64(umemLen),
		Size:     options.frameSize,
		Headroom: options.frameHeadroom,
	}

	err = setOptUmemreg(sockFd, ur)
	if err != nil {
		return errors.Wrap(err, "set umem reg sockopt failed")
	}

	offsets, err := getOptXDPMmapOffsets(sockFd)
	if err != nil {
		return errors.Wrap(err, "get xdp mmap offsets failed")
	}

	err = x.configQueue(offsets, options)

	return err
}

// 清除网卡上的ebpf资源
func clearEbpfProg(ifindex int, xdpMode OptXDPMode) {
	C.unpinEbpfProg(C.int(ifindex), C.int(xdpMode))
}

func loadEbpfProg(ifIndex, xdpMode int, progFd, xsksMapFd *int) error {
	var ret C.int
	var fd, mapFd int
	ret = C.load_ebpf_prog(C.int(ifIndex), C.int(xdpMode),
		unsafe.Pointer(&fd), unsafe.Pointer(&mapFd))
	if ret != 0 {
		return errors.New("load ebpf program failed")
	}
	*progFd = fd
	*xsksMapFd = mapFd
	return nil
}

func addXDPSocketFdToMap(xsksMapFd, sockFd, queueId int) error {
	var ret C.int
	log.Debugf("xsksMapFd:%v, sockFd:%v, queueId:%v", xsksMapFd, sockFd, queueId)
	ret = C.set_ebpf_map(C.int(xsksMapFd), C.int(queueId), C.int(sockFd))
	if ret != 0 {
		return errors.New("add XDP socket fd to xsks_map failed")
	}
	return nil
}

func delXDPSocketFdFromMap(xsksMapFd, queueId int) error {
	var ret C.int
	ret = C.del_ebpf_map(C.int(xsksMapFd), C.int(queueId))
	if ret != 0 {
		return errors.New("delete XDP socket fd from xsks_map failed")
	}
	return nil
}

// 因内核不支持，故不可用
func checkXsksMapIsEmpty(xsksMapFd int) (bool, error) {
	var ret C.int
	ret = C.check_map_is_empty(C.int(xsksMapFd))
	if ret == 0 {
		return true, nil
	}
	if ret < 0 {
		return false, errors.New("check failed")
	}

	return false, nil
}

// 初始化清理工作
// mount -t bpf bpffs /sys/fs/bpf/
func checkIfMountBpffs() bool {
	out, err := executeCommand("mount | grep bpf")

	return err == nil && len(out) > 0
}

func checkAndMountBpffs() error {
	isMount := checkIfMountBpffs()
	if isMount {
		return nil
	}

	_, err := executeCommand("mount -t bpf bpffs /sys/fs/bpf/")
	if err != nil {
		return err
	}
	return nil
}

// exist: true; not exist: false
func checkIfXsksMapFileExist(fileName string) bool {
	err := syscall.Access(fileName, syscall.F_OK)
	if err != nil {
		return false
	}

	return true
}

// rm -f /sys/fs/bpf/xsks_map
func clearXsksMapFile(ifName string) bool {
	xsksMapPath := C.SOCK_MAP_PATH
	fileName := path.Join(xsksMapPath, ifName)
	if !checkIfXsksMapFileExist(fileName) {
		_, err := executeCommand(fmt.Sprintf("rm -f %s", fileName))
		return err == nil
	}

	return true
}

func executeCommand(command string) (string, error) {
	cmd := exec.Command("/usr/bin/bash", "-c", command)
	output, err := cmd.CombinedOutput()

	if err != nil && len(output) > 0 {
		err = fmt.Errorf("execute command(%v) failed; result:%v, error:%v", command, string(output), err)
	}
	log.Debugf("execute command(%v) output: %v", command, string(output))

	return string(output), nil
}

func getInterfaceChannels(ifName string) (int, error) {
	cmdString := fmt.Sprintf("ethtool --show-channels %v | tail -n 2 | awk '{print $2}' | head -n 1",
		ifName)
	output, err := executeCommand(cmdString)
	if err != nil {
		return -1, err
	}

	actualQueue, err := strconv.Atoi(strings.TrimSuffix(output, "\n"))
	if err != nil {
		return -1, err
	}

	return actualQueue, nil
}

func getInterfaceRSS(ifName string) (int, error) {
	cmdString := fmt.Sprintf("ethtool --show-rxfh-indir %v | head -n 1",
		ifName)
	output, err := executeCommand(cmdString)
	if err != nil {
		return -1, err
	}

	reg, err := regexp.Compile("indirection table for (.*) with ([0-9]+) RX ring")
	if err != nil {
		return -1, err
	}

	result := reg.FindStringSubmatch(strings.TrimSuffix(output, "\n"))
	if len(result) < 3 {
		return -1, fmt.Errorf("\"%v\" match regexp(%v) failed(%v) !!!", output, reg.String(), result)
	}
	log.Debugf("reg string: %v", result)
	name := result[1]
	rings := result[2]
	actualQueue, err := strconv.Atoi(strings.TrimSuffix(rings, "\n"))
	if err != nil {
		return -1, err
	}

	if name == ifName {
		return actualQueue, nil
	}
	return -1, fmt.Errorf("error interface name, input(%s) vs. actual(%s)", ifName, name)
}

func setInterfaceRecvQueues(ifIndex int, queueCount uint32) error {
	iface, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return err
	}

	channels, err := getInterfaceChannels(iface.Name)
	if err != nil {
		return err
	}

	queues, err := getInterfaceRSS(iface.Name)
	if err != nil {
		return err
	}

	if queueCount != uint32(channels) || queues != channels {
		if uint32(channels) > queueCount {
			_, err = executeCommand(fmt.Sprintf("ethtool --set-rxfh-indir %v equal %v", iface.Name, queueCount))
			if err != nil {
				return err
			}

			_, err = executeCommand(fmt.Sprintf("ethtool --set-channels %v combined %v", iface.Name, queueCount))
			if err != nil {
				return err
			}
		} else { // case uint32(channels) < queueCount
			_, err = executeCommand(fmt.Sprintf("ethtool --set-channels %v combined %v", iface.Name, queueCount))
			if err != nil {
				return err
			}

			_, err = executeCommand(fmt.Sprintf("ethtool --set-rxfh-indir %v equal %v", iface.Name, queueCount))
			if err != nil {
				return err
			}
		}
	}

	log.Debugf("interface %v rx queues setting: %v", iface.Name, showInterfaceRecvQueues(iface.Name))
	return nil
}

func showInterfaceRecvQueues(ifName string) string {
	cmdString := fmt.Sprintf("ethtool --show-channels %v", ifName)
	rings, err := executeCommand(cmdString)
	if err != nil {
		log.Debugf("execute command %v failed", cmdString)
		return ""
	}

	cmdString = fmt.Sprintf("ethtool --show-rxfh-indir %v", ifName)
	rss, err := executeCommand(cmdString)
	if err != nil {
		log.Debugf("execute command %v failed", cmdString)
		return ""
	}
	log.Debugf(string(rings) + string(rss))

	return string(rings) + string(rss)
}

func initXDPRunningEnv(ifName string, xdpMode OptXDPMode) error {
	mode := "xdp"
	if xdpMode == XDP_MODE_SKB {
		mode = "xdpgeneric"
	}
	cmdString := fmt.Sprintf("ip link set %v %v off", ifName, mode)
	_, err := executeCommand(cmdString)
	if err != nil {
		return err
	}

	err = checkAndMountBpffs()
	if err != nil {
		log.Debugf("mount bpffs failed")
		return err
	}

	log.Info("init XDP running environment ok!!!")
	return nil
}

// 在指定网卡上，创建并配置XDP socket
// 每个socket均使用独立的UMEM，不支持多个socket共享UMEM
func newXDPSocket(ifIndex int, options *XDPOptions, queueId int) (*XDPSocket, error) {
	var err error
	if ifIndex < 0 || options == nil || queueId < 0 {
		return nil, errors.New("error parameters")
	}

	s := XDPSocket{
		sockFd:    -1,
		ifIndex:   ifIndex,
		progFd:    -1,
		xsksMapFd: -1,
		queueId:   queueId,
		xdpMode:   options.xdpMode,
	}
	// goto之后不能定义变量，否则编译报错
	addr := &unix.SockaddrXDP{}

	// 创建AF_XDP类型的socket
	s.sockFd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		err = fmt.Errorf("create unix.Socket failed as %v", err)
		goto failed
	}

	// 配置XDP socket内核相关参数，并初始化用户态队列结构
	err = s.configXDPSocket(options)
	if err != nil {
		err = fmt.Errorf("config XDPSocket failed as %v", err)
		goto failed
	}

	// 将XDP socket绑定到指定端口的特定队列
	addr.Flags = unix.XDP_ZEROCOPY
	addr.Ifindex = uint32(s.ifIndex)
	addr.QueueID = uint32(s.queueId)
	if s.xdpMode == XDP_MODE_SKB {
		// 虚拟机使用SKB模式，仅能支持XDP_COPY
		addr.Flags = unix.XDP_COPY
	}
	err = unix.Bind(s.sockFd, addr)
	if err != nil {
		err = fmt.Errorf("bind socket(%v) with addr(Flags:%v, Ifindex:%v, QueueID:%v) to interface(%v) failed as %v",
			s.sockFd, addr.Flags, addr.Ifindex, addr.QueueID, s.ifIndex, err)
		goto failed
	}

	return &s, nil

failed:
	s.close()
	return nil, err
}

func (s *XDPSocket) CheckEbpfProgLoaded() bool {
	return s.progFd != ERROR_FD
}

// 在同一个网卡的不同队列上创建的sockets共享一个底层ebpf程序，故称这些
// sockets为combined socket
// 此函数，检查s是否需要初始化为combined的combined socket
func (s *XDPSocket) checkAndSetCombinedSocket(combined *XDPSocket) error {
	if combined == nil {
		return errors.New("not need check as this is a new socket")
	}

	if s.ifIndex == combined.ifIndex && s.xdpMode == combined.xdpMode &&
		s.queueId != combined.queueId &&
		combined.progFd != ERROR_FD && combined.xsksMapFd != ERROR_FD {

		s.progFd = combined.progFd
		s.xsksMapFd = combined.xsksMapFd
		return nil
	}
	return errors.New("not combined socket")
}

func (s *XDPSocket) initXDPSocket(loadProg bool) error {
	var err error

	if loadProg {
		// 加载ebpf程序到内核
		err = loadEbpfProg(s.ifIndex, int(s.xdpMode),
			&s.progFd, &s.xsksMapFd)
		if err != nil {
			return err
		}
	}

	if s.sockFd == ERROR_FD || s.xsksMapFd == ERROR_FD || s.queueId == ERROR_FD {
		return fmt.Errorf("error XDPSocket %v", s)
	}
	err = addXDPSocketFdToMap(s.xsksMapFd, s.sockFd, s.queueId)

	return err
}

func (s *XDPSocket) clearXsksMap() {
	if s.xsksMapFd == ERROR_FD {
		return
	}

	err := delXDPSocketFdFromMap(s.xsksMapFd, s.queueId)
	if err != nil {
		log.Debugf("delete xsks_map failed as %v", err)
		return
	}

	log.Infof("delete socket(%v), queueId(%v) from xsks_map(%v)",
		s.sockFd, s.queueId, s.xsksMapFd)
}

func (s *XDPSocket) clearResource() {
	if s == nil {
		return
	}

	if s.xsksMapFd != ERROR_FD {
		unix.Close(s.xsksMapFd)
		log.Infof("close xsksMapFd(%v)", s.xsksMapFd)
		s.xsksMapFd = ERROR_FD
	}

	if s.progFd != ERROR_FD {
		unix.Close(s.progFd)
		s.progFd = ERROR_FD
		log.Infof("close prog_fd(%v)", s.progFd)
	}

	clearEbpfProg(s.ifIndex, s.xdpMode)
	log.Infof("clear ebpf prog(ifIndex:%v, xdpMode:%v) from interface(%v)!!!",
		s.ifIndex, s.xdpMode, s.ifIndex)
}

func (s *XDPSocket) CheckIfXDPSocketClosed() bool {
	return s.sockFd < 0 || s.progFd < 0 || s.xsksMapFd < 0
}

// 关闭XDP socket，并清除资源
func (s *XDPSocket) close() {
	if s == nil {
		return
	}

	if s.sockFd < 0 {
		return
	}

	s.clearXsksMap()

	unix.Munmap(s.framesBulk)

	// 关闭socket
	unix.Close(s.sockFd)
	log.Infof("close xdp socket(%v)", s.sockFd)
	s.sockFd = ERROR_FD
}

func (s XDPSocket) String() string {
	return fmt.Sprintf("\nXDPSocket:\n\tsockFd:%v, ifIndex:%v, framesBulk:%p, "+
		"queueId:%v, xdpMode:%v, "+
		"progFd:%v, xsksMapFd:%v\n\trx:%v\n\ttx:%v\n\tfq:%v\n\tcq:%v\n",
		s.sockFd, s.ifIndex, s.framesBulk,
		s.queueId, s.xdpMode,
		s.progFd, s.xsksMapFd, s.rx, s.tx, s.fq, s.cq)
}
