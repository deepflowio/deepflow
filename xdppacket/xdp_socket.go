// +build linux,xdp

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
	int i, ret, key = 0;
	pthread_t pt;
	int fd = -1, map_fd = -1;
	char pwd[256];

	if (!prog_fd || !xsks_map_fd)
	{
		fprintf(stderr, "ERROR: NULL pointer\n");
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
	if (!access(SOCK_MAP_PATH, F_OK)) {
		if(bpf_map__pin(map, SOCK_MAP_PATH)) {
			fprintf(stderr, "ERROR: pin map xsks_map to xdp/xsks_map\n");
			goto failed;
		}
	}
	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(map_fd));
        goto failed;
	}

	if (bpf_set_link_xdp_fd(ifindex, fd, xdp_mode) < 0) {
			fprintf(stderr, "ERROR: link set xdp fd failed\n");
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
	"reflect"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const ERROR_FD = -1

// XDP socket结构
type XDPSocket struct {
	sockFd     int
	ifIndex    int
	framesBulk []byte // 包缓存
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

	// RX
	addrs := make([]uint64, ringSize)
	baseAddr := ringSize * frameSize
	for i := 0; i < ringSize; i++ {
		addrs[i] = uint64(baseAddr + i*frameSize)
	}
	log.Debugf("init fq addrs:%v\n", addrs)
	err = x.fq.enqueue(addrs, uint32(ringSize))
	if err != nil {
		return errors.Wrapf(err, "fill rx fill queue failed")
	}

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
	sockFd := x.sockFd
	umemLen := options.frameSize * options.numFrames * 2
	buffer := make([]byte, umemLen)
	x.framesBulk = buffer
	ur := &unix.XDPUmemReg{
		Addr:     uint64(reflect.ValueOf(buffer).Pointer()),
		Len:      uint64(umemLen),
		Size:     options.frameSize,
		Headroom: options.frameHeadroom,
	}

	err := setOptUmemreg(sockFd, ur)
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
	cmd := exec.Command("/usr/bin/bash", "-c", "mount | grep bpf")
	out, _ := cmd.Output()

	return len(out) > 0
}

func checkAndMountBpffs() bool {
	isMount := checkIfMountBpffs()
	if isMount == true {
		return true
	}

	cmd := exec.Command("/usr/bin/bash", "-c", "mount -t bpf bpffs /sys/fs/bpf/")
	out, _ := cmd.Output()
	if len(out) > 0 {
		return false
	}

	isMount = checkIfMountBpffs()
	if isMount == false {
		return false
	}

	return true
}

// rm -f /sys/fs/bpf/xsks_map
func checkIfXsksMapFileExist() bool {
	xsksMapPath := C.SOCK_MAP_PATH
	cmd := exec.Command("/usr/bin/bash", "-c", "ls", xsksMapPath)
	out, _ := cmd.Output()
	return len(out) > 0
}

func clearXsksMapFile() bool {
	xsksMapPath := C.SOCK_MAP_PATH
	if !checkIfXsksMapFileExist() {
		cmd := exec.Command("/usr/bin/bash", "-c", "rm -f", xsksMapPath)
		err := cmd.Run()
		return err == nil
	}

	return true
}

func setInterfaceRecvQueues(ifName string, queueCount uint32) bool {
	cmdString := fmt.Sprintf("ethtool --set-rxfh-indir %v equal %v", ifName, queueCount)
	cmd := exec.Command("/usr/bin/bash", "-c", cmdString)
	err := cmd.Run()
	if err != nil {
		log.Debugf("set interface(%v) rx queues(%v) failed", ifName, queueCount)
		return false
	}
	return true
}

func showInterfaceRecvQueues(ifName string) string {
	cmdString := fmt.Sprintf("ethtool --show-rxfh-indir %v", ifName)
	cmd := exec.Command("/usr/bin/bash", "-c", cmdString)
	output, err := cmd.Output()
	if err != nil {
		log.Debugf("execute command %v failed", cmdString)
		return ""
	}
	return string(output)
}

func initXDPRunningEnv(ifName string, xdpMode OptXDPMode, queueCount uint32) bool {
	mode := "xdp"
	if xdpMode == XDP_MODE_SKB {
		mode = "xdpgeneric"
	}
	cmdString := fmt.Sprintf("ip link set %v %v off", ifName, mode)
	cmd := exec.Command("/usr/bin/bash", "-c", cmdString)
	if err := cmd.Run(); err != nil {
		log.Debugf("command %v execute failed as %v", cmdString, err)
	}

	if !clearXsksMapFile() {
		log.Debugf("xsks_map file existed")
		return false
	}

	if !checkAndMountBpffs() {
		log.Debugf("mount bpffs failed")
		return false
	}

	log.Info("init XDP running environment ok!!!")
	return true
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
	addr := &unix.SockaddrXDP{} // goto之后不能定义变量，否则编译报错

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
	addr.Flags = 0
	addr.Ifindex = uint32(s.ifIndex)
	addr.QueueID = uint32(s.queueId)
	if s.xdpMode == XDP_MODE_SKB {
		addr.Flags |= unix.XDP_COPY // 虚拟机使用SKB模式，仅能支持XDP_COPY
	}
	err = unix.Bind(s.sockFd, addr)
	if err != nil {
		err = fmt.Errorf("bind socket(%v) to interface(%v) failed as %v",
			s.sockFd, s.ifIndex, err)
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

func (s *XDPSocket) initXDPSocket(loadProg bool, queueCount uint32) error {
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

	iface, err := net.InterfaceByIndex(s.ifIndex)
	if err != nil {
		return fmt.Errorf("error interface index(%v) as %v", err)
	}
	if !setInterfaceRecvQueues(iface.Name, queueCount) {
		log.Debugf("set interface(%v) recv queues to [0,%v) failed", iface.Name, queueCount)
		return fmt.Errorf("set interface(%v) recv queues to [0,%v) failed", iface.Name, queueCount)
	}
	log.Debugf("interface %v rx queues setting: %v", iface.Name, showInterfaceRecvQueues(iface.Name))

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

func (s *XDPSocket) checkIfXDPSocketClosed() bool {
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
